import importlib.util
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

SHOW_MAP = "<show><user><ip-user-mapping><all/></ip-user-mapping></user></show>"
SHOW_TAGS = "<show><object><registered-ip><all/></registered-ip></object></show>"


def uid(payload):
    return f"<uid-message><version>2.0</version><type>update</type><payload>{payload}</payload></uid-message>"


@pytest.fixture(scope="module")
def base_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), emulator.Handler)
    Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture(autouse=True)
def clean():
    emulator.state.clear()
    emulator.state.update(emulator.load(emulator.SCENARIOS / "healthy.json"))
    emulator.API_KEY = ""
    yield
    emulator.API_KEY = ""


def post(base_url, **fields):
    data = urllib.parse.urlencode(fields).encode()
    return fromstring(urllib.request.urlopen(base_url + "/api", data=data).read())


def show(base_url, cmd):
    url = base_url + "/api?" + urllib.parse.urlencode({"type": "op", "cmd": cmd})
    return fromstring(urllib.request.urlopen(url).read())


def tag_names(base_url):
    return sorted(m.text for m in show(base_url, SHOW_TAGS).findall("result/entry/tag/member"))


def test_login_appears_in_ip_user_mapping(base_url):
    post(base_url, type="user-id", cmd=uid('<login><entry name="corp\\jsmith" ip="10.10.10.11"/></login>'))
    entry = show(base_url, SHOW_MAP).find("result/entry")
    assert entry.find("ip").text == "10.10.10.11"
    assert entry.find("user").text == "corp\\jsmith"
    assert entry.find("type").text == "XMLAPI"


def test_logout_removes_mapping(base_url):
    post(base_url, type="user-id", cmd=uid('<login><entry name="u" ip="10.0.0.1"/></login>'))
    post(base_url, type="user-id", cmd=uid('<logout><entry name="u" ip="10.0.0.1"/></logout>'))
    assert show(base_url, SHOW_MAP).find("result/count").text == "0"


def test_login_replaces_the_user_on_the_same_ip(base_url):
    post(base_url, type="user-id", cmd=uid('<login><entry name="a" ip="10.0.0.1"/></login>'))
    post(base_url, type="user-id", cmd=uid('<login><entry name="b" ip="10.0.0.1"/></login>'))
    assert show(base_url, SHOW_MAP).find("result/entry/user").text == "b"


def test_register_and_unregister_one_tag(base_url):
    post(base_url, type="user-id", cmd=uid(
        '<register><entry ip="10.0.0.1"><tag><member>staff</member><member>hq</member></tag></entry></register>'))
    assert tag_names(base_url) == ["hq", "staff"]
    post(base_url, type="user-id", cmd=uid(
        '<unregister><entry ip="10.0.0.1"><tag><member>staff</member></tag></entry></unregister>'))
    assert tag_names(base_url) == ["hq"]


def test_unregister_without_tags_drops_the_ip(base_url):
    post(base_url, type="user-id", cmd=uid('<register><entry ip="10.0.0.1"><tag><member>x</member></tag></entry></register>'))
    post(base_url, type="user-id", cmd=uid('<unregister><entry ip="10.0.0.1"/></unregister>'))
    assert show(base_url, SHOW_TAGS).find("result/count").text == "0"


def test_expired_entries_are_dropped():
    emulator.userid_apply(uid('<login><entry name="u" ip="10.0.0.1" timeout="1"/></login>'
                              '<register><entry ip="10.0.0.1"><tag><member timeout="1">t</member></tag></entry></register>'))
    emulator.userid_expire(now=emulator.time.time() + 61)
    assert emulator.userid_tables() == ({}, {})


def test_timeout_zero_never_expires():
    emulator.userid_apply(uid('<login><entry name="u" ip="10.0.0.1" timeout="0"/></login>'))
    emulator.userid_expire(now=emulator.time.time() + 10**9)
    assert "10.0.0.1" in emulator.userid_tables()[0]


def test_malformed_message_is_an_error_status(base_url):
    assert post(base_url, type="user-id", cmd="<oops").get("status") == "error"


def test_keygen_works_without_a_key_when_auth_is_on(base_url):
    emulator.API_KEY = "s3cret"
    assert post(base_url, type="keygen", user="a", password="b").find("result/key").text == "s3cret"
    with pytest.raises(urllib.error.HTTPError):
        urllib.request.urlopen(base_url + "/api?type=op&cmd=" + urllib.parse.quote(SHOW_MAP))
