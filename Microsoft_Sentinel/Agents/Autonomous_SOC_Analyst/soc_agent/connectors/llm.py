"""Claude (Anthropic Messages API) as the report writer, called over plain HTTPS."""
from __future__ import annotations

import httpx

from .base import ConnectorError, LLM
from .http import request_json

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"


class ClaudeLLM(LLM):
    name = "claude"

    def __init__(self, api_key: str, model: str, client: httpx.AsyncClient):
        self.api_key, self.model, self.client = api_key, model, client
        self.name = f"Claude ({model})"

    async def complete(self, system: str, prompt: str, max_tokens: int = 1500) -> str:
        data = await request_json(
            self.client, "POST", ANTHROPIC_URL, retries=1,
            headers={"x-api-key": self.api_key, "anthropic-version": ANTHROPIC_VERSION,
                     "content-type": "application/json"},
            json={"model": self.model, "max_tokens": max_tokens, "system": system,
                  "messages": [{"role": "user", "content": prompt}]})
        parts = [b.get("text", "") for b in (data or {}).get("content", []) if b.get("type") == "text"]
        text = "".join(parts).strip()
        if not text:
            raise ConnectorError("Claude returned an empty response")
        return text
