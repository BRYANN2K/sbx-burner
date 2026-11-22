from pathlib import Path

from lab import miniyaml

ROOT = Path(__file__).resolve().parent.parent


def _workload_kits():
    for path in sorted(ROOT.glob("kits/*/*.yaml")):
        data = miniyaml.load(path)
        if data.get("kind") == "workload":
            yield path, data


def test_workload_kits_exist():
    assert {p.parent.name for p, _ in _workload_kits()} >= {"base-kali", "base-ubuntu", "base-remnux"}


def test_workload_kits_grant_no_runtime_egress():
    """Package mirrors must not be open to the agent for the whole run.

    Recipes list install-time hosts in run.network.install_allow instead.
    """
    for path, data in _workload_kits():
        for cap in data.get("capabilities") or []:
            if str(cap.get("type", "")).startswith("com.docker.sandbox/network-policy"):
                runtime = ((cap.get("config") or {}).get("runtime") or {}).get("allow")
                assert not runtime, f"{path.relative_to(ROOT)} opens {runtime} at run time"
