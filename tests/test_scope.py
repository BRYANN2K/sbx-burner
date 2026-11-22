import datetime as dt

import pytest

from lab import miniyaml, scope
from tests.conftest import SCOPE_OK

TODAY = dt.date(2026, 11, 21)


def _load(mutate=None, today=TODAY):
    data = miniyaml.loads(SCOPE_OK)
    if mutate:
        mutate(data)
    return scope.validate(data, today=today)


def test_valid_scope_and_policy():
    s = _load()
    assert s.id == "unit-lab" and s.mode == "strict"
    assert s.target_hosts == ["juice.lab.internal:3000", "10.0.5.0/24"]
    policy = scope.network_policy(s, extra_allow=["api.anthropic.com:443", "10.0.5.9"])
    assert policy["allow"] == ["api.anthropic.com:443", "juice.lab.internal:3000", "10.0.5.0/24", "mirror.lab.internal"]
    assert policy["deny"] == ["10.0.5.9"]
    assert "dos" in s.techniques_forbidden and "exploit" in s.techniques_forbidden


def test_in_scope_matching():
    s = _load()
    assert s.in_scope("juice.lab.internal:3000")
    assert s.in_scope("juice.lab.internal")
    assert not s.in_scope("juice.lab.internal:8080")
    assert s.in_scope("10.0.5.20")
    assert not s.in_scope("10.0.5.9"), "deny wins"
    assert not s.in_scope("10.0.6.1")
    assert not s.in_scope("example.com")


def test_wildcard_matching():
    assert scope._matches("*.lab.internal", "a.lab.internal")
    assert not scope._matches("*.lab.internal", "a.b.lab.internal")
    assert scope._matches("**.lab.internal", "a.b.lab.internal")
    assert not scope._matches("*.lab.internal", "lab.internal.evil.com")


@pytest.mark.parametrize("today", [dt.date(2025, 12, 31), dt.date(2027, 1, 1)])
def test_dates_enforced(today):
    with pytest.raises(scope.ScopeError, match="valid"):
        _load(today=today)


def _set(path, value):
    def mutate(data):
        node = data
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value

    return mutate


@pytest.mark.parametrize(
    "mutate,needle",
    [
        (_set(["targets", 0, "hosts"], ["example.com"]), "not a private lab address"),
        (_set(["targets", 0, "hosts"], ["*"]), "matches every host"),
        (_set(["targets", 0, "hosts"], ["**"]), "matches every host"),
        (_set(["targets", 0, "hosts"], ["https://juice.lab.internal"]), "not a URL"),
        (_set(["targets", 0, "hosts"], ["10.0.0.0/8"]), "wider than /16"),
        (_set(["targets", 0, "hosts"], ["::/0"]), "wider than /48"),
        (_set(["targets", 0, "hosts"], ["2001:db8::/32"]), "wider than /48"),
        (_set(["targets", 0, "hosts"], []), "needs 'hosts' or 'paths'"),
        (_set(["targets"], []), "at least 1"),
        (_set(["authorization"], {"type": "written"}), "needs a 'reference'"),
        (_set(["techniques", "allowed"], ["dos"]), "never allowed"),
        (_set(["valid", "not_after"], "2028-01-01"), "longer than one year"),
        (_set(["valid", "not_after"], "2025-01-01"), "before not_before"),
        (_set(["network", "allow"], ["*.com"]), "whole top-level domain"),
        (_set(["extra"], 1), "unexpected key"),
    ],
)
def test_refusals(mutate, needle):
    with pytest.raises(scope.ScopeError, match=needle):
        _load(mutate)


def test_written_authorization_allows_public_hosts():
    def mutate(data):
        data["authorization"] = {"type": "written", "reference": "https://bounty.example/program/acme"}
        data["targets"][0]["hosts"] = ["app.acme-corp.com", "*.api.acme-corp.com"]

    s = _load(mutate)
    assert s.in_scope("app.acme-corp.com") and s.in_scope("v1.api.acme-corp.com")


def test_wide_ipv6_is_refused_even_with_written_authorization():
    def mutate(data):
        data["authorization"] = {"type": "written", "reference": "https://bounty.example/program/acme"}
        data["targets"][0]["hosts"] = ["::/0"]

    with pytest.raises(scope.ScopeError, match="wider than /48"):
        _load(mutate)

    def narrow(data):
        data["authorization"] = {"type": "written", "reference": "https://bounty.example/program/acme"}
        data["targets"][0]["hosts"] = ["2001:db8:1::/48"]

    assert _load(narrow).in_scope("2001:db8:1::5")


def test_lab_host_classification():
    for host in ("localhost:8080", "127.0.0.1", "192.168.1.5:22", "10.1.0.0/16", "a.test", "x.y.internal", "*.lab"):
        assert scope.is_lab_host(host), host
    for host in ("example.com", "8.8.8.8", "internal.example.com", "testing.org"):
        assert not scope.is_lab_host(host), host


def test_load_missing_and_json(tmp_path):
    with pytest.raises(scope.ScopeError, match="not found"):
        scope.load(tmp_path / "nope.yaml")
    import json

    path = tmp_path / "scope.json"
    path.write_text(json.dumps(miniyaml.loads(SCOPE_OK)), encoding="utf-8")
    assert scope.load(path, today=TODAY).id == "unit-lab"
