"""anthropic-api profile: a tool-less host behind HostPlanner. Request shape,
pricing, fail-closed answers and the run's call, cost and time bounds are tested
with a fake SDK client (no network); a scripted model drives a real IDOR
contrast through the confined tools (VER-015, VER-017, VER-023, VER-028)."""

from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import pytest

from appsec_verifier.agent import AgentProbe, HostPlanner, HostUnavailable, agent_registry
from appsec_verifier.agent.host_anthropic import AnthropicHost
from appsec_verifier.agent.prompts import _tool_defs
from appsec_verifier.agent.steps import STEP_SCHEMA
from appsec_verifier.auth import SessionManager
from appsec_verifier.cli import ProfileError, _build_planner_factory
from appsec_verifier.limits import LimitExceeded, Limits, RunBudget
from appsec_verifier.loader import FindingPlan
from appsec_verifier.scope import ScopeGuard
from appsec_verifier.tools import GuardedHttpClient
from appsec_verifier.verify.probes import ProbeContext

PRICES = {"input_usd_per_million": 4.0, "output_usd_per_million": 20.0,
          "cache_write_usd_per_million": 8.0, "cache_read_usd_per_million": 0.2}


def _wire(action, **args):
    return {"action": action, "args_json": json.dumps(args)}


def _msg(step=None, *, blocks=None, stop="end_turn", usage=(1000, 200, None, None)):
    if blocks is None:
        blocks = [SimpleNamespace(type="thinking", thinking=""), SimpleNamespace(type="text", text=json.dumps(step))]
    keys = ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
    usage = SimpleNamespace(**dict(zip(keys, usage, strict=True)))
    return SimpleNamespace(content=blocks, stop_reason=stop, usage=usage)


class FakeClient:
    """Stands in for anthropic.Anthropic: records with_options and create calls."""

    def __init__(self, script):
        self.script, self.calls, self.options = list(script), [], []
        self.messages = self

    def with_options(self, **options):
        self.options.append(options)
        return self

    @property
    def models(self):
        return SimpleNamespace(retrieve=self.retrieve)

    def retrieve(self, model, **kwargs):          # models.retrieve: the metadata check (VER-032)
        self.calls.append({"retrieve": model})
        out = self.script.pop(0) if self.script else None
        if isinstance(out, Exception):
            raise out
        return out

    def create(self, **kwargs):
        self.calls.append(kwargs)
        out = self.script.pop(0)
        if isinstance(out, Exception):
            raise out
        return out


def _host(script):
    client = FakeClient(script)
    return AnthropicHost(model="claude-opus-5-5", prices=PRICES, client=client), client


def _ctx(limits=None, clock=None):
    plan = SimpleNamespace(id="T-1", cwe="CWE-639", cls="access-control", title="idor",
                           instance="routes/basket.ts:1", reason="scenario")
    budget = RunBudget(limits or Limits(), **({"clock": clock} if clock else {}))
    return SimpleNamespace(plan=plan, identities=[{"role": "customer-a"}], target_base="https://shop.example.com",
                           safe=True, budget=budget)


def test_tool_defs_expose_only_the_confined_tools():
    names = {t["name"] for t in _tool_defs()}
    assert names == {"http_request", "read_source", "browser_check", "submit_verdict",
                     "read_context", "read_response", "plan_test"}
    verdict = next(t for t in _tool_defs() if t["name"] == "submit_verdict")
    assert "confirmed" in verdict["input_schema"]["properties"]["verdict"]["enum"]


def test_request_is_tool_less_structured_bounded_and_priced():
    host, client = _host([_msg(_wire("http_request", path="/x"), usage=(1000, 200, 100, 3000))])
    reply = host.call("system", "prompt", 42.0, _ctx().budget)
    assert reply.step == _wire("http_request", path="/x") and reply.error is None
    assert reply.usd == pytest.approx((1000 * 4 + 200 * 20 + 100 * 8 + 3000 * 0.2) / 1_000_000)
    sent = client.calls[0]
    assert "tools" not in sent and "tool_choice" not in sent
    assert sent["output_config"] == {"format": {"type": "json_schema", "schema": STEP_SCHEMA}}
    assert sent["model"] == "claude-opus-5-5" and sent["system"] == "system"
    assert sent["messages"] == [{"role": "user", "content": "prompt"}]
    assert client.options == [{"timeout": 42.0, "max_retries": 0}]     # bounded, never retried past the bound


class StatusError(Exception):
    def __init__(self, status):
        super().__init__("provider prose that must not reach the report")
        self.status_code = status


class APITimeoutError(Exception):
    pass


@pytest.mark.parametrize("answer, expected", [
    (StatusError(401), "authentication_failed (HTTP 401)"),
    (StatusError(429), "rate_limit (HTTP 429)"),
    (StatusError(529), "server_error (HTTP 529)"),
    (APITimeoutError("slow"), "timeout"),
    (_msg(_wire("http_request", path="/x"), stop="refusal"), "refused"),
    (_msg(_wire("http_request", path="/x"), stop="max_tokens"), "output_truncated"),
    (_msg(blocks=[SimpleNamespace(type="text", text="{}"), SimpleNamespace(type="text", text="{}")]),
     "invalid_response"),
    (_msg(blocks=[SimpleNamespace(type="tool_use", name="bash", input={}),
                  SimpleNamespace(type="text", text=json.dumps(_wire("http_request", path="/x")))]),
     "invalid_response"),
    (_msg(blocks=[SimpleNamespace(type="text", text="not json")]), "invalid_response"),
    (_msg(_wire("http_request", path="/x"), usage=(-1, 200, None, None)), "invalid_response"),
])
def test_failures_end_the_finding_with_a_fixed_reason(answer, expected):
    host, _ = _host([answer])
    reply = host.call("s", "p", 10, _ctx().budget)
    assert reply.error == expected and reply.step is None
    assert "prose" not in reply.error


HAIKU = {"input_usd_per_million": 0.10, "output_usd_per_million": 0.50, "cache_write_usd_per_million": 0.20,
         "cache_read_usd_per_million": 0.01,
         "long_prompt": {"threshold_tokens": 100_000, "input_usd_per_million": 0.50, "output_usd_per_million": 2.50,
                         "cache_write_usd_per_million": 1.00, "cache_read_usd_per_million": 0.05}}


@pytest.mark.parametrize("usage, rates", [
    ((100_000, 500, None, None), (0.10, 0.50, 0.20, 0.01)),            # exactly at the threshold: short rates
    ((100_001, 500, None, None), (0.50, 2.50, 1.00, 0.05)),            # over it: long rates for every token
    ((1_000, 500, 40_000, 60_000), (0.50, 2.50, 1.00, 0.05)),          # cache reads and writes count
    ((1_000, 500, 39_000, 60_000), (0.10, 0.50, 0.20, 0.01)),
])
def test_a_long_prompt_is_priced_at_the_long_prompt_rates(usage, rates):
    host = AnthropicHost(model="claude-haiku-5-5", prices=HAIKU,
                         client=FakeClient([_msg(_wire("http_request", path="/x"), usage=usage)]))
    reply = host.call("s", "p", 10, _ctx().budget)
    tokens = [t or 0 for t in usage]
    assert reply.usd == pytest.approx(sum(t * r for t, r in zip(tokens, rates, strict=True)) / 1_000_000)


def test_every_catalog_model_has_complete_prices():
    import yaml

    from appsec_verifier.version_info import resource_root

    keys = {"input_usd_per_million", "output_usd_per_million", "cache_write_usd_per_million",
            "cache_read_usd_per_million"}
    models = yaml.safe_load((resource_root() / "data" / "anthropic-model-catalog.yaml").read_text())["models"]
    assert {"claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-fable-5-1"} <= set(models)
    for entry in models.values():
        assert keys <= set(entry) and all(entry[k] > 0 for k in keys)
        if "long_prompt" in entry:
            assert set(entry["long_prompt"]) == keys | {"threshold_tokens"}
            assert all(entry["long_prompt"][k] >= entry[k] for k in keys)


def test_profile_needs_a_key_a_priced_model_and_the_sdk(monkeypatch):
    env = {"ANTHROPIC_API_KEY": "sk-test"}
    with pytest.raises(HostUnavailable):
        AnthropicHost.resolve(model=None, environ={}, client_factory=lambda e: FakeClient([]))
    with pytest.raises(HostUnavailable, match="no price"):
        AnthropicHost.resolve(model="claude-unpriced-9", environ=env, client_factory=lambda e: FakeClient([]))
    assert AnthropicHost.resolve(model="claude-sonnet-5-5", environ=env,
                                 client_factory=lambda e: FakeClient([])).prices["input_usd_per_million"] == 2.0
    monkeypatch.setitem(sys.modules, "anthropic", None)           # the optional package is missing
    with pytest.raises(HostUnavailable, match="install appsec-verifier"):
        AnthropicHost.resolve(model=None, environ=env)


def test_profile_selection_builds_a_host_planner(monkeypatch):
    from appsec_verifier.agent import host_anthropic

    monkeypatch.setattr(host_anthropic, "_default_client", lambda environ: FakeClient([]))
    args = SimpleNamespace(model=None, profile="anthropic-api", non_interactive=True, cost_limit=None)
    with pytest.raises(ProfileError):
        _build_planner_factory(args, environ={})
    factory, info = _build_planner_factory(args, environ={"ANTHROPIC_API_KEY": "sk-test"})
    assert isinstance(factory(), HostPlanner)
    assert info == {"profile": "anthropic-api", "model": "claude-sonnet-5-5", "runtime": "Anthropic API",
                    "auth": "API key", "check": "model metadata accessible", "api_billing": True}


# ── the run's bounds now apply to this profile (they did not before) ──────────

def test_call_cap_stops_further_model_calls():
    host, client = _host([_msg(_wire("http_request", path="/x"))] * 2)
    ctx = _ctx(Limits(max_calls=1))
    HostPlanner(host).next_step(ctx, [])
    with pytest.raises(LimitExceeded) as exc:
        HostPlanner(host).next_step(ctx, [])
    assert exc.value.kind == "calls" and len(client.calls) == 1


def test_cost_ceiling_stops_further_model_calls():
    # 1000 input + 200 output tokens = $0.008 per call at the Opus 5.5 rate
    host, client = _host([_msg(_wire("http_request", path="/x"))] * 3)
    ctx = _ctx(Limits(cost_limit_usd=0.01))
    HostPlanner(host).next_step(ctx, [])
    with pytest.raises(LimitExceeded):
        HostPlanner(host).next_step(ctx, [])                  # charged $0.016 > $0.01
    with pytest.raises(LimitExceeded) as exc:
        HostPlanner(host).next_step(ctx, [])                  # refused before the call
    assert exc.value.kind == "cost" and len(client.calls) == 2


def test_timeout_is_the_remaining_run_time():
    host, client = _host([_msg(_wire("http_request", path="/x"))])
    ctx = _ctx(Limits(max_duration_s=1800), clock=iter([0.0, 1790.0]).__next__)
    HostPlanner(host).next_step(ctx, [])
    assert client.options[0]["timeout"] == pytest.approx(10.0)


def test_an_invalid_step_is_refused_before_anything_runs():
    host, _ = _host([_msg(_wire("http_request", path="/x", headers={"X-Forwarded-For": "127.0.0.1"}))])
    action = HostPlanner(host).next_step(_ctx(), [])
    assert action["verdict"]["verdict"] == "inconclusive" and "invalid http_request" in action["verdict"]["rationale"]


def test_agent_registry_covers_classes():
    reg = agent_registry(lambda: None)
    assert reg.get("access-control") is not None and reg.get("xss") is not None


# ── integration: scripted model drives a real two-identity IDOR contrast ──────

class Resp:
    def __init__(self, status=200, text='{"id":2,"UserId":2}'):
        self.status_code = status
        self.text = text
        self.headers = {}


def _full_ctx(tmp_path, transport):
    scope = {"base_url": "https://shop.example.com", "hosts": ["shop.example.com"], "ports": [443],
             "schemes": ["https"], "path_prefixes": ["/"]}
    (tmp_path / "routes").mkdir(exist_ok=True)
    (tmp_path / "routes" / "basket.ts").write_text("get('/rest/basket/:id')\n")
    from appsec_verifier.agent import SourceReader
    http = GuardedHttpClient(ScopeGuard(scope), RunBudget(Limits()), transport)
    idents = [{"role": "customer-a", "method": "bearer", "auth": {"token_env": "TA"}},
              {"role": "customer-b", "method": "bearer", "auth": {"token_env": "TB"}}]
    sessions = SessionManager(idents, http, env={"TA": "AAAA", "TB": "BBBB"})
    plan = FindingPlan(id="T-001", cwe="CWE-639", severity="High", title="idor",
                       match_key="routes/basket.ts|CWE-639", instance="routes/basket.ts:1",
                       status="dynamic", cls="access-control", reason="p")
    return ProbeContext(plan=plan, scope=scope, guard=ScopeGuard(scope), budget=RunBudget(Limits()),
                        http=http, identities=idents, callback={}, safe=True, read_only=True,
                        sessions=sessions, source=SourceReader(tmp_path), target_base=scope["base_url"])


def test_scripted_model_confirms_idor_through_tools(tmp_path):
    calls = []

    def transport(m, u, h, **k):
        calls.append(h.get("Authorization"))
        return Resp()

    host, client = _host([
        _msg(_wire("plan_test", kind="access-control", hypothesis="A reads the known basket of B",
                   path="/rest/basket/2", resource="basket")),
        _msg(_wire("http_request", role="customer-a", path="/rest/basket/2")),
        _msg(_wire("http_request", role="customer-b", path="/rest/basket/2")),
        _msg(_wire("submit_verdict", verdict="confirmed", confidence="high", rationale="a read b",
                   identities_used=["customer-a", "customer-b"], proof_steps=[2, 3])),
    ])
    ctx = _full_ctx(tmp_path, transport)
    ctx.scope = {**ctx.scope, "test_resources": [{"id": "basket", "finding_id": "T-001", "path": "/rest/basket/2",
                 "allowed_roles": ["customer-b"], "denied_roles": ["customer-a"], "pointer": "/UserId", "value": 2}]}
    res = AgentProbe("access-control", lambda: HostPlanner(host), max_steps=8).run(ctx)
    assert res.verdict == "confirmed" and res.identities_used == ["customer-a", "customer-b"]
    assert calls == ["Bearer AAAA", "Bearer BBBB"]
    assert ctx.budget.calls == 4 and ctx.budget.cost == pytest.approx(4 * 0.008)
    assert '"status": 200' in client.calls[2]["messages"][0]["content"]   # results reach the model as data
