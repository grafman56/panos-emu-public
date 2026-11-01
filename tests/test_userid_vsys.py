"""User-ID is per vsys: the same address can belong to two tenants.

A campus firewall carries a tenant vsys and the shared vsys. If the mapping
table were flat, a login in one would answer a policy check in the other.
"""
import importlib.util
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement

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
    emu.state["vsys"] = ["vsys1", "vsys2"]
    yield
    emu.state.clear()
    emu.state.update(saved)


def send(payload, vsys=None):
    return emu.userid_apply(WRAP % payload, vsys)


def rule(name, **fields):
    e = Element("entry", {"name": name})
    for key, value in fields.items():
        child = SubElement(e, key)
        for member in value.split(","):
            SubElement(child, "member").text = member
    emu.apply_change("set", "security/rules/entry[@name='%s']" % name, e)


def match(src, vsys=None):
    return emu.policy_match(
        {"from": ["trust"], "to": ["dc"], "application": ["ssh"], "source": [src]}, "", vsys
    )


def mapping(vsys):
    return {e.findtext("ip"): (e.findtext("user"), e.findtext("vsys"))
            for e in emu.userid_mappings(vsys) if e.tag == "entry"}


def test_same_address_in_two_vsys_is_two_users():
    assert send('<login><entry name="alice@a.edu" ip="10.0.0.5"/></login>', "vsys1")[0]
    assert send('<login><entry name="bob@b.edu" ip="10.0.0.5"/></login>', "vsys2")[0]
    assert mapping("vsys1") == {"10.0.0.5": ("alice@a.edu", "vsys1")}
    assert mapping("vsys2") == {"10.0.0.5": ("bob@b.edu", "vsys2")}


def test_logout_in_one_vsys_leaves_the_other():
    send('<login><entry name="alice@a.edu" ip="10.0.0.5"/></login>', "vsys1")
    send('<login><entry name="bob@b.edu" ip="10.0.0.5"/></login>', "vsys2")
    assert send('<logout><entry ip="10.0.0.5"/></logout>', "vsys1")[0]
    assert mapping("vsys1") == {}
    assert mapping("vsys2") == {"10.0.0.5": ("bob@b.edu", "vsys2")}


def test_policy_match_reads_the_queried_vsys():
    rule("alice-ssh", source="any", destination="any", application="ssh", action="allow",
         **{"source-user": "alice@a.edu"})
    send('<login><entry name="alice@a.edu" ip="10.0.0.5"/></login>', "vsys1")
    assert match("10.0.0.5", "vsys1")["action"] == "allow"
    assert match("10.0.0.5", "vsys2")["action"] == "deny"


def test_ip_tag_in_one_vsys_does_not_answer_in_another():
    rule("staff", source="any", destination="any", application="ssh", action="allow",
         **{"source-tag": "role:staff"})
    send('<register><entry ip="10.0.0.9"><tag><member>role:staff</member></tag></entry></register>', "vsys1")
    assert match("10.0.0.9", "vsys1")["action"] == "allow"
    assert match("10.0.0.9", "vsys2")["action"] == "deny"


def test_user_tags_are_per_vsys():
    rule("bldg", source="any", destination="any", application="ssh", action="allow",
         **{"source-tag": "building_1"})
    send('<login><entry name="jsmith@campus.edu" ip="10.0.0.20"/></login>', "vsys1")
    send('<login><entry name="jsmith@campus.edu" ip="10.0.0.21"/></login>', "vsys2")
    send('<register-user><entry user="jsmith@campus.edu"><tag><member>building_1</member></tag></entry></register-user>', "vsys2")
    # The tag was set in vsys2 only. The same user in vsys1 does not hold it.
    assert match("10.0.0.21", "vsys2")["action"] == "allow"
    assert match("10.0.0.20", "vsys1")["action"] == "deny"


def test_clearing_user_tags_in_one_vsys_leaves_the_other():
    rule("bldg", source="any", destination="any", application="ssh", action="allow",
         **{"source-tag": "building_1"})
    for v, ip in (("vsys1", "10.0.0.20"), ("vsys2", "10.0.0.21")):
        send('<login><entry name="j@campus.edu" ip="%s"/></login>' % ip, v)
        send('<register-user><entry user="j@campus.edu"><tag><member>building_1</member></tag></entry></register-user>', v)
    assert send('<clear><registered-user><all/></registered-user></clear>', "vsys2")[0]
    assert match("10.0.0.21", "vsys2")["action"] == "deny"
    assert match("10.0.0.20", "vsys1")["action"] == "allow"


def test_write_to_an_unknown_vsys_is_refused():
    ok, message = send('<login><entry name="a@x" ip="10.0.0.1"/></login>', "vsys9")
    assert not ok and message == "unknown vsys: vsys9"
    assert mapping("vsys1") == {}


def test_show_for_an_unknown_vsys_raises():
    with pytest.raises(ValueError):
        emu.userid_mappings("vsys9")


def test_the_dispatcher_turns_an_unknown_vsys_into_error_18():
    vsys, failure = emu.vsys_or_error({"vsys": ["vsys9"]})
    assert vsys is None and failure is not None
    assert b"unknown vsys" in failure and b'code="18"' in failure


def test_default_vsys_is_vsys1():
    send('<login><entry name="a@x" ip="10.0.0.1"/></login>')
    assert mapping(None) == {"10.0.0.1": ("a@x", "vsys1")}
    assert match("10.0.0.1", None)["action"] in ("allow", "deny")
