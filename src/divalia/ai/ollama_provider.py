from __future__ import annotations

from divalia.ai.base_provider import HTTPProvider, ProviderError


class OllamaProvider(HTTPProvider):
    async def generate(self, prompt: str, *, system: str = "", role: str = "heavy") -> str:
        if len(prompt) > 100_000 or len(system) > 20_000:
            raise ProviderError("inference input exceeds limit")
        value = await self.request(
            "/api/generate",
            {
                "model": self.model(role),
                "prompt": prompt,
                "system": system,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0, "num_predict": 4096},
            },
        )
        output = value.get("response") if isinstance(value, dict) else None
        if not isinstance(output, str) or len(output) > 100_000:
            raise ProviderError("Ollama returned invalid/oversized response text")
        return output

    async def status(self) -> dict:
        value = await self.request("/api/tags", None)
        if not isinstance(value, dict) or not isinstance(value.get("models"), list):
            raise ProviderError("Ollama returned an invalid model listing")
        return value

    async def pull(self, model: str, *, consent: bool = False) -> dict:
        if not consent:
            raise PermissionError("model downloads require explicit operator consent")
        if not model or len(model) > 160 or any(c.isspace() for c in model):
            raise ValueError("invalid model name")
        # Pulls can be slow; still bounded by the configured HTTP timeout.
        value = await self.request("/api/pull", {"model": model, "stream": False})
        if not isinstance(value, dict) or value.get("status") != "success":
            raise ProviderError("Ollama did not confirm a completed model pull")
        return value
