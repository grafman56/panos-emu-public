import importlib.util
import json
import urllib.error
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
    emulator.state.clear()
    emulator.state.update(emulator.load(emulator.SCENARIOS / "healthy.json"))
    emulator.jobs.clear()
    yield
    emulator.API_KEY = ""


def request(base_url, path, method="GET", body=None, headers=None):
    data = body.encode() if body is not None else None
    req = urllib.request.Request(base_url + path, data=data, method=method, headers=headers or {})
    try:
        resp = urllib.request.urlopen(req)
        return resp.status, resp.headers.get("Content-Type", ""), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type", ""), e.read()


def test_routing_root(base_url):
    status, ctype, body = request(base_url, "/")
    assert status == 200
    assert ctype.startswith("text/html")


def test_routing_health(base_url):
    status, ctype, body = request(base_url, "/health")
    assert status == 200
    assert fromstring(body).find("result/status").text == "up"


def test_routing_unknown_path(base_url):
    status, ctype, body = request(base_url, "/nonexistent-path")
    assert status == 404


def test_routing_version(base_url):
    status, ctype, body = request(base_url, "/api?type=version")
    assert status == 200
    assert ctype.startswith("application/xml")
    assert b"<version>" in body


def test_auth_no_key_rejected(base_url):
    emulator.API_KEY = "test-key"
    status, ctype, body = request(base_url, "/api?type=version")
    assert status == 403
    assert fromstring(body).get("status") == "error"


def test_auth_header_key_accepted(base_url):
    emulator.API_KEY = "test-key"
    status, ctype, body = request(base_url, "/api?type=version", headers={"X-PAN-KEY": "test-key"})
    assert status == 200


def test_auth_query_key_accepted(base_url):
    emulator.API_KEY = "test-key"
    status, ctype, body = request(base_url, "/api?type=version&key=test-key")
    assert status == 200


def test_auth_wrong_key_rejected(base_url):
    emulator.API_KEY = "test-key"
    status, ctype, body = request(base_url, "/api?type=version", headers={"X-PAN-KEY": "wrong"})
    assert status == 403


def test_auth_health_bypasses_gate(base_url):
    emulator.API_KEY = "test-key"
    status, ctype, body = request(base_url, "/health")
    assert status == 200


def test_scenario_switch(base_url):
    status, ctype, body = request(base_url, "/scenario/healthy", method="POST")
    assert status == 200
    assert b"healthy" in body
    status, ctype, body = request(base_url, "/api?type=version")
    assert status == 200


def test_scenario_not_found(base_url):
    status, ctype, body = request(base_url, "/scenario/does-not-exist", method="POST")
    assert status == 404
    assert fromstring(body).get("code") == "7"


def test_scenario_path_traversal_blocked(base_url):
    status, ctype, body = request(base_url, "/scenario/../../etc/passwd", method="POST")
    assert status == 404


def test_restapi_get(base_url):
    status, ctype, body = request(base_url, "/restapi/v11.0/Policies/SecurityRules")
    assert status == 200
    assert ctype.startswith("application/json")
    assert json.loads(body)["resource"] == "SecurityRules"


def test_config_set_validate_delete(base_url):
    element = "<entry><source>trust</source><destination>untrust</destination><application>dns</application><action>allow</action></entry>"
    xpath = "security/rules/entry[@name='t1']"
    path = f"/api?type=config&action=set&xpath={urllib.parse.quote(xpath)}&element={urllib.parse.quote(element)}"

    status, ctype, body = request(base_url, path, method="POST")
    assert status == 200

    # duplicate add is an update, not an error
    status, ctype, body = request(base_url, path, method="POST")
    assert status == 200

    status, ctype, body = request(base_url, "/api?type=config&action=validate")
    assert status == 200
    assert b"validation passed" in body

    status, ctype, body = request(base_url, f"/api?type=config&action=delete&xpath={urllib.parse.quote(xpath)}", method="POST")
    assert status == 200

    status, ctype, body = request(base_url, "/api?type=config&action=show")
    assert "t1" not in [entry.get("name") for entry in fromstring(body).findall(".//entry")]


def test_config_set_unsupported_xpath(base_url):
    xpath = "address/entry[@name='x']"
    path = f"/api?type=config&action=set&xpath={urllib.parse.quote(xpath)}&element={urllib.parse.quote('<entry/>')}"
    status, ctype, body = request(base_url, path, method="POST")
    assert status == 200
    assert fromstring(body).get("code") == "6"


def test_config_set_malformed_xml(base_url):
    xpath = "security/rules/entry[@name='bad']"
    path = f"/api?type=config&action=set&xpath={urllib.parse.quote(xpath)}&element={urllib.parse.quote('not-xml<')}"
    status, ctype, body = request(base_url, path, method="POST")
    assert fromstring(body).get("code") == "18"
