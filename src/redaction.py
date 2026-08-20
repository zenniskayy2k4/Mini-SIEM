import re


_SECRET = re.compile(
    r"(?i)\b(api[_-]?key|authorization|cookie|password|secret|token)\b\s*[:=]\s*[^\s,;]+"
)
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")


def redact_text(value, limit=1200):
    text = " ".join(str(value if value is not None else "N/A").split())[:limit]
    text = _BEARER.sub("Bearer [REDACTED]", text)
    return _SECRET.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
