"""Policy that matches on who is at the source address (User-ID)."""
import importlib.util
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, fromstring

import pytest

spec = importlib.util.spec_from_file_location("emulator", Path(__file__).parents[1] / "panos_emulator.py")
emu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(emu)

WRAP = "<uid-message><version>1.0</version><type>update</type><payload>%s</payload></uid-message>"


@pytest.fixture(autouse=True)
def clean():
    saved = emu.state.copy()
    emu.state.clear()
    emu.state["candidate_config"] = {"security-rules": []}
    yield
    emu.state.clear()
    emu.state.update(saved)


def rule(name, **fields):
    e = Element("entry", {"name": name})
    for k, v in fields.items():
        c = SubElement(e, k)
        for member in v.split(","):  # PAN-OS writes lists as <member> elements
            SubElement(c, "member").text = member
    emu.apply_change("set", "security/rules/entry[@name='%s']" % name, e)


def match(src):
    return emu.policy_match({"from": ["trust"], "to": ["dc"], "application": ["ssh"], "source": [src]})


def send(payload):
    return emu.userid_apply(WRAP % payload)


def test_rule_on_source_tag_follows_the_tag():
    rule("staff-ssh", source="any", destination="any", application="ssh", action="allow", **{"source-tag": "role:staff"})
    assert match("10.10.10.100")["action"] == "deny"
    send('<register><entry ip="10.10.10.100"><tag><member>role:staff</member></tag></entry></register>')
    assert match("10.10.10.100")["action"] == "allow"
    assert match("10.10.10.101")["action"] == "deny"  # a different address
    send('<unregister><entry ip="10.10.10.100"><tag><member>role:staff</member></tag></entry></unregister>')
    assert match("10.10.10.100")["action"] == "deny"


def test_rule_on_source_user():
    rule("jsmith-ssh", source="any", destination="any", application="ssh", action="allow", **{"source-user": "jsmith@campus.edu"})
    send('<login><entry name="jsmith@campus.edu" ip="10.10.10.100"/></login>')
    send('<login><entry name="other@campus.edu" ip="10.10.10.101"/></login>')
    assert match("10.10.10.100")["action"] == "allow"
    assert match("10.10.10.101")["action"] == "deny"
    send('<logout><entry name="jsmith@campus.edu" ip="10.10.10.100"/></logout>')
    assert match("10.10.10.100")["action"] == "deny"


def test_user_tag_applies_to_every_address_of_the_user():
    rule("bldg", source="any", destination="any", application="ssh", action="allow", **{"source-tag": "building_1"})
    send('<login><entry name="jsmith@campus.edu" ip="10.10.10.100"/></login>'
         '<login><entry name="jsmith@campus.edu" ip="10.10.10.101"/></login>')
    send('<register-user><entry user="jsmith@campus.edu"><tag><member>building_1</member></tag></entry></register-user>')
    assert match("10.10.10.100")["action"] == "allow" and match("10.10.10.101")["action"] == "allow"
    send('<unregister-user><entry user="jsmith@campus.edu"><tag><member>building_1</member></tag></entry></unregister-user>')
    assert match("10.10.10.100")["action"] == "deny"


def test_user_tag_needs_an_existing_mapping():
    ok, msg = send('<register-user><entry user="nobody@campus.edu"><tag><member>x</member></tag></entry></register-user>')
    assert not ok and "no user mapping" in msg


def test_clear_registered_user_removes_all_user_tags():
    send('<login><entry name="a@x" ip="10.0.0.1"/></login>')
    send('<register-user><entry user="a@x"><tag><member>t</member></tag></entry></register-user>')
    send('<clear><registered-user><all/></registered-user></clear>')
    assert emu.user_tags() == {}


def test_tag_timeout_is_capped_at_30_days():
    ok, _ = send('<register><entry ip="10.0.0.1"><tag><member timeout="2592000">t</member></tag></entry></register>')
    assert ok
    ok, msg = send('<register><entry ip="10.0.0.1"><tag><member timeout="2592001">t</member></tag></entry></register>')
    assert not ok and "timeout" in msg


def test_logout_accepts_user_attribute_too():
    send('<login><entry name="a@x" ip="10.0.0.1"/></login>')
    ok, _ = send('<logout><entry user="a@x" ip="10.0.0.1"/></logout>')
    assert ok and "10.0.0.1" not in emu.userid_tables()[0]
