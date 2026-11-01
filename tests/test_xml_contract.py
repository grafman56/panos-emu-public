"""The XML API as a client library sees it.

These tests encode the shape a PAN-OS client expects, not the shape that is
convenient to produce. Each path here is one that pan-python, the Ansible
panos modules or a Terraform provider walks.
"""
import importlib.util
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from xml.etree.ElementTree import fromstring

import pytest

ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location("emulator", ROOT / "panos_emulator.py")
emulator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(emulator)

CONFIG = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"
RULES = CONFIG + "/rulebase/security/rules"


@pytest.fixture(scope="module")
def base_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), emulator.Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    thread.join()


@pytest.fixture(autouse=True)
def reset_state():
    # The initial device state, so interfaces, routes and licences are present.
    emulator.state.clear()
    emulator.state.update(emulator.load(emulator.DATA))
    emulator.state.setdefault("candidate_config", emulator.deepcopy(
        emulator.state.get("running_config", {})))
    emulator.jobs.clear()
    emulator.API_KEY = ""
    yield
    emulator.API_KEY = ""


def get(base_url, **fields):
    url = base_url + "/api?" + urllib.parse.urlencode(fields)
    return fromstring(urllib.request.urlopen(url).read())


def post(base_url, **fields):
    data = urllib.parse.urlencode(fields).encode()
    return fromstring(urllib.request.urlopen(base_url + "/api", data=data).read())


def op(base_url, cmd):
    return get(base_url, type="op", cmd=cmd)


def rule_names(node):
    return [e.get("name") for e in node.iter("entry") if e.get("name")]


def test_config_show_returns_the_running_tree(base_url):
    document = get(base_url, type="config", action="show")
    config = document.find("result/config")
    assert config is not None, "no /config root"
    vsys = config.find("devices/entry/vsys/entry")
    assert vsys is not None and vsys.get("name") == "vsys1"
    assert rule_names(vsys.find("rulebase/security/rules")) == ["allow-web"]
    assert [e.get("name") for e in vsys.findall("zone/entry")] == ["trust", "untrust", "dmz"]


def test_config_show_is_running_and_get_is_candidate(base_url):
    post(base_url, type="config", action="set",
         xpath="security/rules/entry[@name='candidate-only']",
         element='<entry name="candidate-only"><source>any</source>'
                 '<destination>any</destination><application>ssh</application>'
                 '<action>allow</action></entry>')
    running = get(base_url, type="config", action="show")
    candidate = get(base_url, type="config", action="get")
    assert "candidate-only" not in rule_names(running)
    assert "candidate-only" in rule_names(candidate)


def test_config_show_does_not_mix_candidate_changes_into_the_tree(base_url):
    post(base_url, type="config", action="set",
         xpath="security/rules/entry[@name='x']",
         element='<entry name="x"><action>deny</action></entry>')
    document = get(base_url, type="config", action="show")
    assert document.find("result/config") is not None
    assert document.find("result/candidate-changes") is None
    assert [e.text for e in document.find("result").findall("xpath")] == []


def test_xpath_selects_the_security_rulebase(base_url):
    document = get(base_url, type="config", action="show", xpath=RULES)
    rules = document.find("result/rules")
    assert rules is not None
    assert rule_names(rules) == ["allow-web"]


def test_xpath_selects_the_vsys(base_url):
    document = get(base_url, type="config", action="show", xpath=CONFIG)
    vsys = document.find("result/entry")
    assert vsys is not None and vsys.get("name") == "vsys1"


def test_a_path_outside_config_is_an_error(base_url):
    document = get(base_url, type="config", action="show", xpath="/mgt-config/users")
    assert document.get("status") == "error"
    assert document.get("code") == "6"


def test_an_empty_path_under_config_is_empty_not_an_error(base_url):
    document = get(base_url, type="config", action="show",
                   xpath=CONFIG + "/rulebase/nat")
    assert document.get("status") == "success"
    assert document.find("result/config") is not None


def test_a_rule_holds_its_values_as_members(base_url):
    document = get(base_url, type="config", action="show", xpath=RULES)
    rule = document.find("result/rules/entry")
    assert [m.text for m in rule.findall("source/member")] == ["trust"]
    assert [m.text for m in rule.findall("application/member")] == ["ssl"]
    assert rule.findtext("action") == "allow"


def test_interfaces_are_keyed_by_name(base_url):
    document = op(base_url, "<show><interface><all/></interface></show>")
    entries = document.findall("result/interfaces/entry")
    assert [e.get("name") for e in entries] == ["ethernet1/1", "ethernet1/2"]
    assert entries[0].findtext("zone") == "trust"


def test_routes_live_under_a_virtual_router(base_url):
    document = op(base_url, "<show><routing><route></route></routing></show>")
    router = document.find("result/virtual-router/entry")
    assert router is not None and router.get("name") == "default"
    route = router.find("routing-table/entry")
    assert route.findtext("destination") == "0.0.0.0/0"
    assert route.findtext("nexthop") == "172.100.112.1"


def test_a_bgp_query_is_not_answered_with_static_routes(base_url):
    document = op(base_url, "<show><routing><protocol><bgp><summary/></bgp></protocol></routing></show>")
    assert document.find("result/bgp") is not None
    assert document.find("result/virtual-router") is None


def test_licences_are_keyed_by_name(base_url):
    document = op(base_url, "<show><license></license></show>")
    names = [e.get("name") for e in document.findall("result/licenses/entry")]
    assert names == ["threat-prevention", "wildfire"]
    assert document.find("result/licenses/entry/days-remaining").text == "365"


def test_sessions_keep_their_names(base_url):
    document = op(base_url, "<show><session></session></show>")
    session = document.find("result/session")
    assert session.findtext("active") == "128"
    assert session.findtext("maximum") == "10000"


def test_a_commit_job_reports_status_under_the_job(base_url):
    document = post(base_url, type="commit")
    job_id = document.findtext("result/job")
    assert job_id
    emulator.jobs[job_id]["created"] -= 1
    polled = op(base_url, f"<show><jobs><id>{job_id}</id></jobs></show>")
    job = polled.find("result/job")
    assert job is not None, "status is not nested under job"
    assert job.findtext("status") == "FIN"
    assert job.findtext("result") == "OK"


def test_a_policy_match_names_the_rule(base_url):
    document = get(base_url, type="op", **{"from": "trust", "to": "untrust",
                                           "application": "ssl"})
    entry = document.find("result/rules/entry")
    assert entry.get("name") == "allow-web"
    assert entry.findtext("action") == "allow"


def test_unknown_operational_command_is_an_error(base_url):
    document = op(base_url, "<show><no-such-thing/></show>")
    assert document.get("status") == "error"
    assert document.get("code") == "1"


def test_pan_python_reads_the_config_tree(base_url):
    """Run the real client when it is installed. Skips otherwise."""
    pan = pytest.importorskip("panos")
    from panos.firewall import Firewall
    firewall = Firewall("127.0.0.1", api_port=int(base_url.rsplit(":", 1)[1]))
    rules = firewall.xapi.get(xpath=RULES)
    assert rules.find("result/rules") is not None
    info = firewall.op("<show><system><info></info></system></show>")
    assert info.findtext("result/system/hostname") == "pa-lab-01"
