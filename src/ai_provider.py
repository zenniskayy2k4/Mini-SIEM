from abc import ABC, abstractmethod
from urllib.parse import urlparse

import requests


class AIProvider(ABC):
    name: str
    model: str

    @abstractmethod
    def available(self) -> bool:
        """Return whether the provider is configured for analysis."""

    @abstractmethod
    def analyze(self, messages, schema):
        """Return the provider's text response for structured messages."""

    @property
    def used_name(self):
        return self.name

    @property
    def used_model(self):
        return self.model

    def diagnostics(self):
        return {}


class _OllamaProvider(AIProvider):
    def __init__(
        self, base_url: str, model: str, *, opener=requests.post, https_only=False,
    ):
        self.base_url = str(base_url or "").strip().rstrip("/")
        self.model = str(model or "").strip()
        parsed = urlparse(self.base_url)
        schemes = {"https"} if https_only else {"http", "https"}
        if parsed.scheme not in schemes or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Ollama base URL must be HTTP(S) without credentials, query, or fragment")
        if not self.model or len(self.model) > 200 or any(character.isspace() for character in self.model):
            raise ValueError("Ollama model must be a non-empty model identifier")
        self._opener = opener

    def _headers(self):
        return {"Content-Type": "application/json"}

    def analyze(self, messages, schema):
        if not self.available():
            raise RuntimeError(f"AI provider {self.name} is unavailable")
        if not isinstance(messages, list) or not messages:
            raise ValueError("AI messages must be a non-empty list")
        if not isinstance(schema, (str, dict)):
            raise ValueError("AI response schema must be a string or object")
        response = self._opener(
            f"{self.base_url}/chat",
            headers=self._headers(),
            json={
                "model": self.model,
                "stream": False,
                "format": schema,
                "messages": messages,
                "options": {"temperature": 0.1, "num_predict": 800},
            },
            timeout=120,
        )
        response.raise_for_status()
        payload = response.json()
        content = payload.get("message", {}).get("content", "") if isinstance(payload, dict) else ""
        if not isinstance(content, str) or not content.strip():
            raise RuntimeError("Ollama Cloud returned an empty response")
        return content.strip()


class OllamaCloudProvider(_OllamaProvider):
    name = "ollama_cloud"

    def __init__(
        self, api_key: str, base_url: str = "https://ollama.com/api",
        model: str = "gemma4:cloud", opener=requests.post,
    ):
        self._api_key = str(api_key or "").strip()
        super().__init__(base_url, model, opener=opener, https_only=True)

    def available(self) -> bool:
        return bool(self._api_key)

    def _headers(self):
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }


class OllamaLocalProvider(_OllamaProvider):
    name = "ollama_local"

    def __init__(
        self, base_url: str = "http://host.docker.internal:11434/api",
        model: str = "gemma3:4b", *, opener=requests.post, health_opener=requests.get,
    ):
        super().__init__(base_url, model, opener=opener)
        self._health_opener = health_opener
        self._health_checked = False
        self._healthy = False

    def available(self) -> bool:
        if self._health_checked:
            return self._healthy
        self._health_checked = True
        try:
            response = self._health_opener(f"{self.base_url}/tags", timeout=2)
            response.raise_for_status()
            payload = response.json()
            models = payload.get("models", []) if isinstance(payload, dict) else []
            self._healthy = any(
                isinstance(item, dict) and self.model in {item.get("name"), item.get("model")}
                for item in models
            )
        except Exception:
            self._healthy = False
        return self._healthy


class FallbackAIProvider(AIProvider):
    """Try one primary and one fallback provider once per analysis."""

    name = "fallback"

    def __init__(self, primary: AIProvider, fallback: AIProvider):
        if not isinstance(primary, AIProvider) or not isinstance(fallback, AIProvider):
            raise TypeError("Fallback providers must implement AIProvider")
        if primary.name == fallback.name:
            raise ValueError("Primary and fallback AI providers must be different")
        self._providers = (primary, fallback)
        self.model = " -> ".join(provider.model for provider in self._providers)
        self._last_provider = None
        self._last_attempts = []

    def available(self) -> bool:
        return any(provider.available() for provider in self._providers)

    def analyze(self, messages, schema):
        self._last_provider = None
        self._last_attempts = []
        for provider in self._providers:
            if not provider.available():
                self._last_attempts.append({"provider": provider.name, "status": "unavailable"})
                continue
            try:
                result = provider.analyze(messages, schema)
            except Exception:
                self._last_attempts.append({"provider": provider.name, "status": "failed"})
                continue
            self._last_provider = provider
            self._last_attempts.append({"provider": provider.name, "status": "success"})
            return result
        raise RuntimeError("All configured AI providers are unavailable")

    @property
    def used_name(self):
        return self._last_provider.name if self._last_provider else self.name

    @property
    def used_model(self):
        return self._last_provider.model if self._last_provider else self.model

    def diagnostics(self):
        return {
            "chain": [provider.name for provider in self._providers],
            "last_provider": self._last_provider.name if self._last_provider else None,
            "used": bool(self._last_provider and self._last_provider is self._providers[1]),
            "attempts": list(self._last_attempts),
        }


def _build_ai_provider(
    name, *, api_key, base_url, model, local_base_url, local_model,
):
    if name == OllamaCloudProvider.name:
        return OllamaCloudProvider(api_key, base_url, model)
    if name == OllamaLocalProvider.name:
        return OllamaLocalProvider(local_base_url, local_model)
    raise ValueError(f"Unsupported AI provider: {name or 'empty'}")


def build_ai_provider(
    name, *, api_key, base_url, model,
    local_base_url="http://host.docker.internal:11434/api", local_model="gemma3:4b",
    fallback_name="",
):
    provider_name = str(name or "").strip().lower()
    fallback_name = str(fallback_name or "").strip().lower()
    primary = _build_ai_provider(
        provider_name, api_key=api_key, base_url=base_url, model=model,
        local_base_url=local_base_url, local_model=local_model,
    )
    if not fallback_name:
        return primary
    fallback = _build_ai_provider(
        fallback_name, api_key=api_key, base_url=base_url, model=model,
        local_base_url=local_base_url, local_model=local_model,
    )
    return FallbackAIProvider(primary, fallback)
