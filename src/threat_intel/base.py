from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class ThreatIntelResult:
    ioc_type: str
    ioc: str
    provider: str
    status: str
    checked_at: str
    data: dict[str, Any] = field(default_factory=dict)
    error: dict[str, Any] | None = None
    attempts: int = 1
    duration_ms: int = 0
    cached: bool = False

    def as_dict(self) -> dict:
        return asdict(self)


class ThreatIntelProviderError(Exception):
    def __init__(self, code: str, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.code = str(code or "provider_error")
        self.safe_message = str(message or "Provider lookup failed")
        self.retryable = bool(retryable)


class ThreatIntelProvider(ABC):
    name: str

    @abstractmethod
    def lookup(self, ioc_type: str, ioc: str, timeout_seconds: float) -> dict | None:
        """Return normalized evidence, None when not found, or raise a provider error."""
