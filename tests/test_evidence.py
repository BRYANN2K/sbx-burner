import datetime as dt
import json

from lab import evidence, miniyaml, report, scope
from tests.conftest import SCOPE_OK

# Fake credentials are assembled at run time so that no secret-shaped literal
# is stored in the repository (secret scanners flag them, rightly).
ALNUM = "abcdefghijklmnopqrstuvwxyz" + "0123456789"
FAKE_GH = "gh" + "p_" + ALNUM
FAKE_AWS = "AK" + "IA" + "IOSFODNN7" + "EXAMPLE"
FAKE_PW = "hunter2" * 2
FAKE_BEARER = "Authorization: " + "Bear" + "er " + ALNUM[:26]
FAKE_PEM = "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIabc\n-----END RSA " + "PRIVATE KEY-----"


def _finding(fid="F-1", **over):
    base = {
        "id": fid,
        "title": "Reflected XSS in search",
        "severity": "medium",
        "target": "http://juice.lab.internal:3000/#/search",
        "description": "The q parameter is reflected without encoding.",
        "proof": {"poc": "curl 'http://juice.lab.internal:3000/rest/products/search?q=<x>'", "artifacts": ["artifacts/f1.txt"]},
    }
    base.update(over)
    return base


def _evidence(tmp_path, findings):
    (tmp_path / "artifacts").mkdir(exist_ok=True)
    (tmp_path / "artifacts" / "f1.txt").write_text("HTTP/1.1 200 OK\n<x>", encoding="utf-8")
    data = evidence.empty("pentest/webapp-blackbox", "Tested the search form.")
    data["findings"] = findings
    data["artifacts"] = [{"path": "artifacts/f1.txt", "description": "response"}]
    (tmp_path / "evidence.json").write_text(json.dumps(data), encoding="utf-8")
    return evidence.load(tmp_path)


def test_proven_finding_is_kept_and_artifact_hashed(tmp_path):
    result = evidence.gate(_evidence(tmp_path, [_finding()]), tmp_path)
    assert result.ok and not result.demoted
    assert len(result.evidence["findings"]) == 1
    assert len(result.evidence["artifacts"][0]["sha256"]) == 64


def test_unproven_findings_become_hypotheses(tmp_path):
    findings = [
        _finding("F-nopoc", proof={"poc": "  ", "artifacts": ["artifacts/f1.txt"]}),
        _finding("F-noart", proof={"poc": "curl x", "artifacts": []}),
        _finding("F-missing", proof={"poc": "curl x", "artifacts": ["artifacts/nope.txt"]}),
        _finding("F-escape", proof={"poc": "curl x", "artifacts": ["../../etc/passwd"]}),
        _finding("F-abs", proof={"poc": "curl x", "artifacts": ["/etc/passwd"]}),
        _finding("F-ok"),
    ]
    result = evidence.gate(_evidence(tmp_path, findings), tmp_path)
    assert [f["id"] for f in result.evidence["findings"]] == ["F-ok"]
    reasons = {d["id"]: d["reason"] for d in result.demoted}
    assert reasons["F-nopoc"] == "no PoC"
    assert reasons["F-noart"] == "no artifact"
    assert "missing" in reasons["F-missing"]
    assert "escapes" in reasons["F-escape"] and "escapes" in reasons["F-abs"]
    hyp = {h["id"]: h for h in result.evidence["hypotheses"]}
    assert hyp["H-F-nopoc"]["demoted_from"] == "F-nopoc"


def test_empty_artifact_is_not_proof(tmp_path):
    data = _evidence(tmp_path, [_finding()])
    (tmp_path / "artifacts" / "f1.txt").write_text("", encoding="utf-8")
    assert evidence.gate(data, tmp_path).demoted[0]["reason"].startswith("artifact is empty")


def test_out_of_scope_target_is_demoted(tmp_path):
    s = scope.validate(miniyaml.loads(SCOPE_OK), today=dt.date(2026, 11, 21))
    findings = [_finding("F-in"), _finding("F-out", target="https://example.com/login")]
    result = evidence.gate(_evidence(tmp_path, findings), tmp_path, scope=s)
    assert [f["id"] for f in result.evidence["findings"]] == ["F-in"]
    assert "out of scope" in result.demoted[0]["reason"]


def test_scheme_less_out_of_scope_target_is_demoted(tmp_path):
    s = scope.validate(miniyaml.loads(SCOPE_OK), today=dt.date(2026, 11, 21))
    findings = [
        _finding("F-ip", target="10.9.9.9:8080"),
        _finding("F-name", target="evil.example.com/login"),
        _finding("F-in", target="juice.lab.internal:3000"),
        _finding("F-cidr", target="10.0.5.20"),
        _finding("F-file", target="src/app.py:20"),
        _finding("F-file2", target="app.py:20"),
        _finding("F-label", target="pr-demo"),
    ]
    result = evidence.gate(_evidence(tmp_path, findings), tmp_path, scope=s)
    assert [f["id"] for f in result.evidence["findings"]] == ["F-in", "F-cidr", "F-file", "F-file2", "F-label"]
    reasons = {d["id"]: d["reason"] for d in result.demoted}
    assert "10.9.9.9:8080 is out of scope" in reasons["F-ip"]
    assert "evil.example.com is out of scope" in reasons["F-name"]


def test_cvss_is_recomputed(tmp_path):
    f = _finding(severity="low", cvss={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 5.0})
    result = evidence.gate(_evidence(tmp_path, [f]), tmp_path)
    kept = result.evidence["findings"][0]
    assert kept["cvss"]["score"] == 9.8 and kept["severity"] == "critical"
    assert len(result.warnings) == 2
    bad = _finding(cvss={"vector": "CVSS:3.1/AV:N", "score": 5.0})
    assert "invalid CVSS" in evidence.gate(_evidence(tmp_path, [bad]), tmp_path).demoted[0]["reason"]


def test_schema_errors_block_everything(tmp_path):
    data = _evidence(tmp_path, [_finding(severity="catastrophic")])
    result = evidence.gate(data, tmp_path)
    assert not result.ok and "not one of" in result.schema_errors[0]


def test_redaction():
    text = f"key {FAKE_AWS} and {FAKE_GH} password = '{FAKE_PW}' {FAKE_BEARER} {FAKE_PEM}"
    out, count = evidence.redact(text)
    assert count == 5
    for secret in (FAKE_AWS[4:], ALNUM, FAKE_PW, "MIIabc"):
        assert secret not in out
    assert "AKIA[REDACTED:aws-access-key]" in out
    assert evidence.redact("nothing secret here")[1] == 0


def test_report_is_built_from_gated_evidence_only(tmp_path):
    findings = [
        _finding("F-ok", description=f"token {FAKE_GH} leaked"),
        _finding("F-bad", proof={"poc": "", "artifacts": []}),
    ]
    result = evidence.gate(_evidence(tmp_path, findings), tmp_path)
    rep = report.write(tmp_path, {"id": "r1", "recipe": "pentest/webapp-blackbox", "agent": "claude", "status": "completed"}, result)
    md = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert rep["counts"] == {"findings": 1, "hypotheses": 1, "by_severity": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0}}
    assert "### F-ok" in md and "### F-bad" not in md
    assert "H-F-bad" in md and "demoted from F-bad: no PoC" in md
    assert ALNUM not in md
    assert "Secrets redacted: 1" in md
    assert json.loads((tmp_path / "report.json").read_text())["gate"]["redactions"] == 1
