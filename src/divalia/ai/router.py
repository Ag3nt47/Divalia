from __future__ import annotations

from typing import Any

from divalia.ai.base_provider import BaseProvider, create_provider


class ModelRouter(BaseProvider):
    """Choose a configured adapter per role. No implicit remote fallback or disclosure."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.providers = {
            role: create_provider({**config, **config.get(role, {})}) for role in ("light", "heavy")
        }

    async def generate(self, prompt: str, *, system: str = "", role: str = "heavy") -> str:
        if role not in self.providers:
            raise ValueError("model role must be light or heavy")
        return await self.providers[role].generate(prompt, system=system, role=role)
