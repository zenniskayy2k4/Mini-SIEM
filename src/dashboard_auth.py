import hashlib
import json
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import timedelta
from functools import wraps
from pathlib import Path

from flask import jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

from config import config


ROLES = {"viewer": 1, "analyst": 2, "admin": 3}
_USERNAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_DUMMY_HASH = generate_password_hash("not-a-real-password")
_FAILURES = defaultdict(deque)
_FAILURE_LOCK = threading.Lock()
# ponytail: process-local locking fits the single dashboard process; use DB transactions if scaled out.
_USERS_LOCK = threading.RLock()
MAX_PASSWORD_LENGTH = 256


def init_proxy(app):
    hops = os.getenv("DASHBOARD_TRUSTED_PROXY_HOPS", "0").strip()
    if hops not in {"0", "1"}:
        raise RuntimeError("DASHBOARD_TRUSTED_PROXY_HOPS must be 0 or 1")
    trusted_hosts = [
        host.strip() for host in os.getenv("DASHBOARD_TRUSTED_HOSTS", "").split(",")
        if host.strip()
    ]
    if hops == "1" and not trusted_hosts:
        raise RuntimeError("DASHBOARD_TRUSTED_HOSTS is required when proxy trust is enabled")
    if any(not re.fullmatch(r"\.?[A-Za-z0-9:[\].-]{1,253}", host) for host in trusted_hosts):
        raise RuntimeError("DASHBOARD_TRUSTED_HOSTS contains an invalid host")
    if trusted_hosts:
        app.config["TRUSTED_HOSTS"] = trusted_hosts
    if hops == "1":
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


def _secure_file(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8") as output:
            output.write(value)
    except FileExistsError:
        pass
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path.read_text(encoding="utf-8").strip()


def init_auth(app):
    secret = os.getenv("DASHBOARD_SESSION_SECRET", "").strip()
    if not secret:
        secret = _secure_file(config.DASHBOARD_SESSION_KEY_FILE, secrets.token_hex(32))
    if len(secret) < 32:
        raise RuntimeError("DASHBOARD_SESSION_SECRET must contain at least 32 characters")
    app.config.update(
        SECRET_KEY=secret,
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=config.DASHBOARD_COOKIE_SECURE,
    )


def load_users():
    with _USERS_LOCK:
        try:
            payload = json.loads(Path(config.DASHBOARD_USERS_FILE).read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}


def _write_users(users):
    path = Path(config.DASHBOARD_USERS_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(users, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(temporary, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def save_user(username, password, role, audit=None):
    username = str(username).strip().lower()
    role = str(role).strip().lower()
    if not _USERNAME.fullmatch(username):
        raise ValueError("Username must contain only letters, numbers, dot, dash or underscore")
    if role not in ROLES:
        raise ValueError("Role must be viewer, analyst or admin")
    if not isinstance(password, str) or not 12 <= len(password) <= MAX_PASSWORD_LENGTH:
        raise ValueError(f"Password must contain between 12 and {MAX_PASSWORD_LENGTH} characters")
    with _USERS_LOCK:
        users = load_users()
        previous = users.get(username)
        existed = previous is not None
        users[username] = {"password_hash": generate_password_hash(password), "role": role}
        _write_users(users)
        try:
            if audit:
                audit(existed)
        except Exception as exc:
            if existed:
                users[username] = previous
            else:
                users.pop(username, None)
            _write_users(users)
            raise RuntimeError("User change was rolled back because audit logging failed") from exc
        return existed


def delete_user(username, audit=None):
    username = str(username).strip().lower()
    if not _USERNAME.fullmatch(username):
        raise ValueError("Invalid username")
    with _USERS_LOCK:
        users = load_users()
        if username not in users:
            return False
        previous = users.pop(username)
        _write_users(users)
        try:
            if audit:
                audit()
        except Exception as exc:
            users[username] = previous
            _write_users(users)
            raise RuntimeError("User deletion was rolled back because audit logging failed") from exc
        return True


def get_user(username):
    user = load_users().get(str(username).strip().lower())
    if not isinstance(user, dict) or user.get("role") not in ROLES:
        return None
    if not isinstance(user.get("password_hash"), str):
        return None
    return user


def authenticate(username, password):
    username = str(username).strip().lower()
    if not isinstance(password, str) or len(password) > MAX_PASSWORD_LENGTH:
        return None, None
    user = get_user(username)
    password_hash = user["password_hash"] if user else _DUMMY_HASH
    try:
        valid = check_password_hash(password_hash, str(password))
    except ValueError:
        valid = False
    return (username, user) if user and valid else (None, None)


def user_auth_version(user):
    return hashlib.sha256(user["password_hash"].encode("utf-8")).hexdigest()


def csrf_token():
    return session.setdefault("csrf_token", secrets.token_urlsafe(32))


def csrf_valid(value=None):
    supplied = value or request.headers.get("X-CSRF-Token", "") or request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    return bool(expected and secrets.compare_digest(str(supplied), expected))


def role_required(role):
    def decorate(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            if ROLES.get(session.get("role"), 0) < ROLES[role]:
                return jsonify({"error": "Forbidden"}), 403
            return function(*args, **kwargs)
        return wrapped
    return decorate


# ponytail: in-process throttling fits the single dashboard worker; use a shared store if scaled out.
def login_allowed(key):
    now = time.monotonic()
    with _FAILURE_LOCK:
        failures = _FAILURES[key]
        while failures and failures[0] < now - 60:
            failures.popleft()
        return len(failures) < 5


def record_login_failure(key):
    with _FAILURE_LOCK:
        if len(_FAILURES) > 1000:
            _FAILURES.clear()
        _FAILURES[key].append(time.monotonic())


def clear_login_failures(key):
    with _FAILURE_LOCK:
        _FAILURES.pop(key, None)
