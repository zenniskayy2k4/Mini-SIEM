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


class OllamaCloudProvider(AIProvider):
    name = "ollama_cloud"

    def __init__(
        self, api_key: str, base_url: str = "https://ollama.com/api",
        model: str = "gemma4:cloud", opener=requests.post,
    ):
        self._api_key = str(api_key or "").strip()
        self.base_url = str(base_url or "").strip().rstrip("/")
        self.model = str(model or "").strip()
        parsed = urlparse(self.base_url)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.query or parsed.fragment:
            raise ValueError("Ollama Cloud base URL must be an HTTPS URL without credentials or query")
        if not self.model or len(self.model) > 200 or any(character.isspace() for character in self.model):
            raise ValueError("Ollama Cloud model must be a non-empty model identifier")
        self._opener = opener

    def available(self) -> bool:
        return bool(self._api_key)

    def analyze(self, messages, schema):
        if not self.available():
            raise RuntimeError("Ollama Cloud API key is not configured")
        if not isinstance(messages, list) or not messages:
            raise ValueError("AI messages must be a non-empty list")
        if not isinstance(schema, (str, dict)):
            raise ValueError("AI response schema must be a string or object")
        response = self._opener(
            f"{self.base_url}/chat",
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
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


def build_ai_provider(name, *, api_key, base_url, model):
    provider_name = str(name or "").strip().lower()
    if provider_name != OllamaCloudProvider.name:
        raise ValueError(f"Unsupported AI provider: {provider_name or 'empty'}")
    return OllamaCloudProvider(api_key, base_url, model)
