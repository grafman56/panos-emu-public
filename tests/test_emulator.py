import importlib.util
import time
from pathlib import Path


spec = importlib.util.spec_from_file_location("emulator", Path(__file__).parents[1] / "panos_emulator.py")
emulator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(emulator)


def test_candidate_commit_and_policy_match():
    original = emulator.state.copy()
    try:
        emulator.state["running_config"] = {"security-rules": []}
        emulator.state["candidate_config"] = {"security-rules": []}
        emulator.state["candidate_changes"] = []
        element = emulator.Element("entry", {"name": "allow-dns"})
        emulator.SubElement(element, "source").text = "trust"
        emulator.SubElement(element, "destination").text = "untrust"
        emulator.SubElement(element, "application").text = "dns"
        emulator.SubElement(element, "action").text = "allow"
        emulator.apply_change("set", "security/rules/entry[@name='allow-dns']", element)
        assert emulator.current_config()["security-rules"] == []
        assert emulator.policy_match({"from": ["trust"], "to": ["untrust"], "application": ["dns"]})["action"] == "allow"
        job = emulator.begin_job(True)
        emulator.state["running_config"] = emulator.deepcopy(emulator.candidate_config())
        assert emulator.state["running_config"]["security-rules"][0]["name"] == "allow-dns"
        time.sleep(emulator.JOB_COMPLETE_AFTER + 0.1)
        assert emulator.job_result(job).find(b"FIN") >= 0
    finally:
        emulator.state.clear()
        emulator.state.update(original)


def test_failed_commit_keeps_candidate_change():
    emulator.state["commit"] = {"result": "FAIL"}
    emulator.state["candidate_changes"] = [{"action": "set", "xpath": "bad"}]
    before = emulator.current_config().copy()
    job = emulator.begin_job(False)
    assert emulator.current_config() == before
    time.sleep(emulator.JOB_COMPLETE_AFTER + 0.1)
    assert emulator.job_result(job).find(b"FAIL") >= 0


def test_a_scenario_changes_only_what_it_names():
    """Switching to a failure scenario must not wipe interfaces or routes.

    The scenario files carry the device condition, not the whole device. If the
    switch replaced all state, every exercise started on a device with no
    interfaces and an empty routing table.
    """
    saved = emulator.state.copy()
    emulator.state.clear()
    emulator.state.update(emulator.load(emulator.DATA))
    try:
        emulator.switch_scenario(emulator.SCENARIOS / "ha-out-of-sync.json")
        assert "ethernet1/1" in emulator.state["interfaces"]
        assert emulator.state["virtual-routers"]["default"]["routes"]
        assert emulator.state["ha"]["running-sync"] == "out-of-sync"
    finally:
        emulator.state.clear()
        emulator.state.update(saved)


def test_a_scenario_keeps_published_user_id():
    saved = emulator.state.copy()
    emulator.state.clear()
    emulator.state.update(emulator.load(emulator.DATA))
    try:
        emulator.state["vsys"] = ["vsys1", "vsys2"]
        emulator.userid_tables("vsys2")[0]["10.0.0.1"] = {"user": "a@x", "timeout": 0, "created": 0, "expires": 0}
        emulator.switch_scenario(emulator.SCENARIOS / "tunnel-down.json")
        assert emulator.state["vsys"] == ["vsys1", "vsys2"]
        assert "10.0.0.1" in emulator.userid_tables("vsys2")[0]
    finally:
        emulator.state.clear()
        emulator.state.update(saved)


def test_bgp_peer_filters():
    e = emulator
    e.state["bgp"] = {"default": {"local-as": 65301, "peers": [{"peer-address": "10.0.0.1", "status": "Established"}]},
                      "guest": {"local-as": 65301, "peers": [{"peer-address": "10.0.1.1", "status": "Idle"}]}}
    try:
        count = lambda cmd: e.bgp_entries(cmd).__len__()
        assert count("") == 2
        assert count("<virtual-router>guest</virtual-router>") == 1
        assert count("<peer-name>peer-10.0.0.1</peer-name><virtual-router>default</virtual-router>") == 1
        assert count("<peer-name>peer-10.0.0.1</peer-name><virtual-router>guest</virtual-router>") == 0
    finally:
        e.state.pop("bgp")
