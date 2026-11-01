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
