"""`codex` profile: the OpenAI Responses API with OPENAI_API_KEY, tool-less, as
AppSec Analyzer's codex profile (VER-023).

Each step is one POST to the fixed Responses endpoint with no tools, strict
structured output for the step schema, and `store: false`. Redirects are not
followed, so the key only ever goes to that endpoint. The cost is computed from
the reported token usage at the installed catalog prices (data/model-catalog.yaml)
and charged against the USD ceiling (VER-015).
"""

from __future__ import annotations

import httpx
import yaml

from ..version_info import resource_root
from .hosts import HostReply, HostUnavailable, check_model_name
from .steps import STEP_SCHEMA, strict_json

ENDPOINT = "https://api.openai.com/v1/responses"
DEFAULT_MODEL = "gpt-sol"
REASONING_EFFORT = "medium"
MAX_OUTPUT_TOKENS = 16_000


def catalog_model(name: str) -> tuple[str, dict]:
    """Resolve an alias or model id from the installed catalog."""
    check_model_name(name)
    with open(resource_root() / "data" / "model-catalog.yaml", encoding="utf-8") as fh:
        catalog = yaml.safe_load(fh) or {}
    model = (catalog.get("aliases") or {}).get(name, name)
    entry = (catalog.get("models") or {}).get(model)
    if not isinstance(entry, dict):
        known = sorted({*(catalog.get("aliases") or {}), *(catalog.get("models") or {})})
        raise HostUnavailable(f"model {name!r} is not in the installed catalog ({', '.join(known)})")
    return model, entry


def _post(url: str, headers: dict, body: dict, timeout: float) -> tuple[int, bytes]:
    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        resp = client.post(url, headers=headers, json=body)
        return resp.status_code, resp.content


class OpenAIHost:
    label = "OpenAI API"
    profile = "codex"

    def __init__(self, *, model: str, prices: dict, api_key: str, post=_post):
        self.model, self.prices, self._key, self._post = model, prices, api_key, post
        self.version, self.auth = "", "API key"
        self.broken: str | None = None

    @classmethod
    def resolve(cls, *, model: str | None, environ, post=_post) -> OpenAIHost:
        key = environ.get("OPENAI_API_KEY")
        if not key:
            raise HostUnavailable("the codex profile needs OPENAI_API_KEY")
        model_id, entry = catalog_model(model or DEFAULT_MODEL)
        return cls(model=model_id, prices=entry, api_key=key, post=post)

    def call(self, system: str, prompt: str, timeout: float, budget) -> HostReply:
        body = {
            "model": self.model,
            "instructions": system,
            "input": prompt,
            "store": False,
            "max_output_tokens": MAX_OUTPUT_TOKENS,
            "reasoning": {"effort": REASONING_EFFORT},
            "text": {"format": {"type": "json_schema", "name": "verification_step", "strict": True,
                                "schema": STEP_SCHEMA}},
        }
        try:
            status, data = self._post(ENDPOINT, {"Authorization": f"Bearer {self._key}"}, body, timeout)
        except httpx.TimeoutException:
            return HostReply(error="timeout")
        except httpx.HTTPError:
            return HostReply(error="connection_failed")
        if status != 200:
            reason = {401: "authentication_failed", 403: "authentication_failed", 429: "rate_limit"}.get(
                status, "server_error" if status >= 500 else "invalid_request")
            return HostReply(error=f"{reason} (HTTP {status})")
        try:
            response = strict_json(data.decode("utf-8"))
            usage = response["usage"]
            tokens_in, tokens_out = usage["input_tokens"], usage["output_tokens"]
            if not all(type(t) is int and t >= 0 for t in (tokens_in, tokens_out)):
                raise ValueError("invalid usage")
            usd = (tokens_in * self.prices["input_usd_per_million"]
                   + tokens_out * self.prices["output_usd_per_million"]) / 1_000_000
        except (ValueError, KeyError, TypeError, UnicodeError, AttributeError):
            return HostReply(error="invalid_response")
        try:
            if response.get("status") != "completed":
                raise ValueError("incomplete")
            content = [part for item in response.get("output") or [] if isinstance(item, dict)
                       and item.get("type") == "message" for part in item.get("content") or []
                       if isinstance(part, dict)]
            if len(content) != 1 or content[0].get("type") != "output_text":
                raise ValueError("refusal or ambiguous output")
            step = strict_json(content[0]["text"])
        except (ValueError, KeyError, TypeError, AttributeError):
            return HostReply(usd=usd, error="invalid_response")
        return HostReply(step=step, usd=usd)
