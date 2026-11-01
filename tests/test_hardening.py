import importlib.util
import socket
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
def addr():
    server = emulator.Server(("127.0.0.1", 0), emulator.Handler)
    Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address
    server.shutdown()


@pytest.fixture(autouse=True)
def clean():
    emulator.state.clear()
    emulator.state.update(emulator.load(emulator.SCENARIOS / "healthy.json"))
    emulator.API_KEY = ""


def raw(addr, data, wait=3):
    s = socket.create_connection(addr, timeout=5)
    s.sendall(data)
    s.settimeout(wait)
    try:
        reply = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            reply += chunk
    except socket.timeout:
        pass
    finally:
        s.close()
    return reply


def status(reply):
    return int(reply.split(b" ", 2)[1]) if reply else 0


def uid(addr, payload):
    body = f"<uid-message><payload>{payload}</payload></uid-message>".encode()
    req = (b"POST /api?type=user-id HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % len(body)) + body
    reply = raw(addr, req)
    return reply, fromstring(reply.split(b"\r\n\r\n", 1)[1])


def test_bad_content_length_is_a_400(addr):
    for value in (b"abc", b"-5"):
        reply = raw(addr, b"POST /api?type=user-id HTTP/1.1\r\nHost: x\r\nContent-Length: " + value + b"\r\n\r\n")
        assert status(reply) == 400, (value, reply[:80])


def test_oversized_body_is_a_413_without_reading_it(addr):
    reply = raw(addr, b"POST /api?type=user-id HTTP/1.1\r\nHost: x\r\nContent-Length: 999999999\r\n\r\n")
    assert status(reply) == 413


def test_non_utf8_body_is_a_400(addr):
    body = b"\xb0\xb1\xb2\xb3"
    reply = raw(addr, b"POST /api?type=user-id HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\n" + body)
    assert status(reply) == 400


def test_a_stalled_client_is_dropped(addr, monkeypatch):
    monkeypatch.setattr(emulator.Handler, "timeout", 1)
    s = socket.create_connection(addr, timeout=5)
    # claims 100 bytes, sends 3, then waits: the server must close on its own
    s.sendall(b"POST /api?type=user-id HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nabc")
    s.settimeout(4)
    try:
        closed = s.recv(4096) == b""
    except socket.timeout:
        closed = False
    finally:
        s.close()
    assert closed, "the server held the connection open"


@pytest.mark.parametrize("entry", [
    '<entry name="u" ip="1.1.1.1" timeout="abc"/>',
    '<entry name="u" ip="1.1.1.1" timeout="-5"/>',
    '<entry name="u" ip="not-an-ip"/>',
    '<entry name="u" ip="999.1.1.1"/>',
])
def test_bad_login_entries_are_an_error_reply(addr, entry):
    reply, doc = uid(addr, f"<login>{entry}</login>")
    assert status(reply) == 200 and doc.get("status") == "error", reply[:120]
    assert emulator.userid_tables()[0] == {}


def test_bad_register_ip_is_an_error_reply(addr):
    reply, doc = uid(addr, '<register><entry ip="x"><tag><member>t</member></tag></entry></register>')
    assert doc.get("status") == "error"
    assert emulator.userid_tables()[1] == {}


def test_a_bad_entry_applies_nothing(addr):
    # all-or-nothing: the good login before the bad one must not land
    reply, doc = uid(addr, '<login><entry name="ok" ip="1.1.1.1"/><entry name="bad" ip="nope"/></login>')
    assert doc.get("status") == "error"
    assert emulator.userid_tables()[0] == {}


def test_valid_ipv6_and_zero_timeout_still_work(addr):
    reply, doc = uid(addr, '<login><entry name="u" ip="2001:db8::1" timeout="0"/></login>')
    assert doc.get("status") == "success"
    assert "2001:db8::1" in emulator.userid_tables()[0]
