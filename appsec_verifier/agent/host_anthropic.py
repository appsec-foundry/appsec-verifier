"""`anthropic-api` profile: the Anthropic Messages API through the `anthropic`
SDK with ANTHROPIC_API_KEY, tool-less, as one host behind HostPlanner
(VER-015, VER-017, VER-023, VER-060).

Each step is one `messages.create` call without tools and with strict
structured output for the step schema (`output_config.format`). HostPlanner
therefore applies the call cap, the cost check before the call, the timeout
(the remaining run time, at most CALL_TIMEOUT_S) and `parse_step` exactly as for
every other profile. The SDK gets that timeout and no retries, so a call never
outlasts its bound. The cost is computed from the reported usage at the prices
in data/anthropic-model-catalog.yaml and charged against the USD ceiling; a
model without a price there is refused. A model priced by prompt length
(Claude Haiku 5.5) has a second rate card, used for a response whose prompt,
cache reads and writes included, is longer than its threshold. SDK errors become fixed reason codes,
so no provider prose reaches the report. `check_access` reads the model's
metadata once, without generating, for the pre-flight check (VER-032).
"""

from __future__ import annotations

import yaml

from ..version_info import resource_root
from .hosts import HostReply, HostUnavailable, check_model_name, png_base64, usage_counts
from .steps import STEP_SCHEMA, strict_json

DEFAULT_MODEL = "claude-sonnet-5-5"
MAX_TOKENS = 16_000
# usage field -> catalog price; writes without lifetime details use the higher 1-hour rate
_PRICED_USAGE = (("input_tokens", "input_usd_per_million"), ("output_tokens", "output_usd_per_million"),
                 ("cache_creation_input_tokens", "cache_write_usd_per_million"),
                 ("cache_read_input_tokens", "cache_read_usd_per_million"))
_ANSWER_BLOCKS = ("text", "thinking", "redacted_thinking")


def catalog_prices(model: str) -> dict:
    """The model's prices from the installed catalog, or HostUnavailable: a model
    whose cost cannot be counted is not used."""
    check_model_name(model)
    with open(resource_root() / "data" / "anthropic-model-catalog.yaml", encoding="utf-8") as fh:
        models = (yaml.safe_load(fh) or {}).get("models") or {}
    entry = models.get(model)
    if not isinstance(entry, dict):
        raise HostUnavailable(f"model {model!r} has no price in data/anthropic-model-catalog.yaml "
                              f"({', '.join(sorted(models))}), so its cost cannot be counted")
    return entry


def _default_client(environ):
    try:
        import anthropic
    except ModuleNotFoundError as exc:
        raise HostUnavailable("the anthropic-api profile needs the 'anthropic' package; "
                              "install appsec-verifier[agent]") from exc
    key = environ.get("ANTHROPIC_API_KEY")
    return anthropic.Anthropic(api_key=key) if key else anthropic.Anthropic()


def _reason(exc: Exception) -> str:
    status = getattr(exc, "status_code", None)
    if isinstance(status, int):
        reason = {401: "authentication_failed", 403: "authentication_failed", 404: "model_unavailable",
                  429: "rate_limit"}.get(
            status, "server_error" if status >= 500 else "invalid_request")
        return f"{reason} (HTTP {status})"
    name = type(exc).__name__
    return {"APITimeoutError": "timeout", "APIConnectionError": "connection_failed"}.get(name, f"host_error ({name})")


class AnthropicHost:
    label = "Anthropic API"
    profile = "anthropic-api"
    api_billing = True      # costs are shown without --show-costs

    def __init__(self, *, model: str, prices: dict, client):
        self.model, self.prices, self._client = model, prices, client
        self.version, self.auth = "", "API key"
        self.broken: str | None = None

    @classmethod
    def resolve(cls, *, model: str | None, environ, client_factory=None) -> AnthropicHost:
        if not (environ.get("ANTHROPIC_API_KEY") or environ.get("ANTHROPIC_AUTH_TOKEN")):
            raise HostUnavailable("the anthropic-api profile needs ANTHROPIC_API_KEY")
        model = model or DEFAULT_MODEL
        prices = catalog_prices(model)
        return cls(model=model, prices=prices, client=(client_factory or _default_client)(environ))

    def check_access(self, timeout: float) -> None:
        """One model metadata request: the API accepts the key and offers the model.
        Generates nothing (VER-032). Raises HostUnavailable with a fixed reason code."""
        try:
            self._client.with_options(timeout=timeout, max_retries=0).models.retrieve(self.model)
        except Exception as exc:  # noqa: BLE001 - any SDK failure is reported by its fixed reason code
            raise HostUnavailable(f"model {self.model}: {_reason(exc)}") from None

    def _cost(self, usage) -> float:
        """USD for one response. A prompt (input, cache writes and cache reads) longer than the
        catalog's `long_prompt.threshold_tokens` is priced at the long-prompt rates."""
        tokens = {}
        for field, _ in _PRICED_USAGE:
            count = getattr(usage, field, None)
            if count is None and field.startswith("cache_"):
                count = 0
            if type(count) is not int or count < 0:
                raise ValueError("invalid usage")
            tokens[field] = count
        prompt = tokens["input_tokens"] + tokens["cache_creation_input_tokens"] + tokens["cache_read_input_tokens"]
        long = self.prices.get("long_prompt")
        prices = long if long is not None and prompt > long["threshold_tokens"] else self.prices
        cost = sum(tokens[field] * prices[price] for field, price in _PRICED_USAGE)
        creation = getattr(usage, "cache_creation", None)
        if creation is not None:
            short = getattr(creation, "ephemeral_5m_input_tokens", None)
            long = getattr(creation, "ephemeral_1h_input_tokens", None)
            if (not all(type(n) is int and n >= 0 for n in (short, long))
                    or short + long != tokens["cache_creation_input_tokens"]):
                raise ValueError("invalid cache usage")
            cost += short * (prices["cache_write_5m_usd_per_million"] - prices["cache_write_usd_per_million"])
        return cost / 1_000_000

    supports_images = True   # PNG screenshots of an evidence review (VER-042)

    def call(self, system: str, prompt: str, timeout: float, budget, *, schema=None, images=()) -> HostReply:
        content = prompt if not images else [
            *({"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": png_base64(image)}}
              for image in images),
            {"type": "text", "text": prompt}]
        try:
            resp = self._client.with_options(timeout=timeout, max_retries=0).messages.create(
                model=self.model, max_tokens=MAX_TOKENS,
                system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral", "ttl": "5m"}}],
                messages=[{"role": "user", "content": content}],
                output_config={"format": {"type": "json_schema", "schema":
                                          schema if schema is not None else STEP_SCHEMA}},
            )
        except Exception as exc:  # noqa: BLE001 - any SDK failure ends this finding with a fixed reason code
            return HostReply(error=_reason(exc))
        try:
            usd = self._cost(resp.usage)
        except (AttributeError, KeyError, TypeError, ValueError):
            return HostReply(error="invalid_response")
        usage = usage_counts(resp.usage)
        if resp.stop_reason != "end_turn":
            reason = {"refusal": "refused", "max_tokens": "output_truncated"}.get(resp.stop_reason, "invalid_response")
            return HostReply(usd=usd, error=reason, usage=usage)
        try:
            blocks = list(resp.content)
            texts = [b.text for b in blocks if b.type == "text"]
            if len(texts) != 1 or any(b.type not in _ANSWER_BLOCKS for b in blocks):
                raise ValueError("no single text answer")
            step = strict_json(texts[0])
        except (AttributeError, TypeError, ValueError):
            return HostReply(usd=usd, error="invalid_response", usage=usage)
        return HostReply(step=step, usd=usd, usage=usage)
