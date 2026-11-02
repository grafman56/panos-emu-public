#!/usr/bin/env python3
"""Small, data-driven PAN-OS XML API emulator for Containerlab training."""

import hmac
import ipaddress
import json
import os
import re
import threading
import time
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse
from xml.etree.ElementTree import Element, ParseError, SubElement, fromstring, tostring

ROOT = Path(__file__).parent
DATA = Path(os.getenv("PANOS_DATA", ROOT / "data" / "default.json"))
SCENARIOS = ROOT / "scenarios"
API_KEY = os.getenv("PANOS_API_KEY", "")


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def switch_scenario(path):
    """Apply one scenario file to the device state.

    A scenario names what changes, such as HA state or a licence date. Merge it
    over the base fixture so interfaces, routes and configuration stay as they
    were. Replacing the whole state made every scenario look like a wiped
    device. The vsys list and the User-ID tables survive too. Configuration does
    not: each scenario carries its own running configuration."""
    # Process settings and live User-ID tables outlive a change of condition:
    # a published login is not part of "the HA pair went out of sync".
    keep = {k: state[k] for k in ("vsys", "userid_logins", "userid_tags", "userid_user_tags") if k in state}
    merged = load(DATA)
    merged.update(load(path))
    merged.update(keep)
    state.clear()
    state.update(merged)
    jobs.clear()
    apply_lab_baseline()


state = load(DATA)
state.setdefault("candidate_config", deepcopy(state.get("running_config", {})))

# Lab mirror: PANOS_LAB_FW names a running Containerlab firewall node. Its
# interfaces, zones, routes, BGP peers and session count replace the sample
# data. See lab_snapshot.py.
LAB_FW = os.getenv("PANOS_LAB_FW", "")
LAB_REFRESH_SECONDS = 3
_lab = {"at": 0.0, "failed": False}


def refresh_lab(force=False):
    """Copy the firewall node's live state into `state`. Keep the last copy on failure."""
    if not LAB_FW or (not force and time.monotonic() - _lab["at"] < LAB_REFRESH_SECONDS):
        return
    _lab["at"] = time.monotonic()
    try:
        import lab_snapshot
        snap = lab_snapshot.snapshot(LAB_FW)
    except Exception as exc:  # docker missing, node down: serve the last good copy
        if not _lab["failed"]:
            print(f"lab mirror: cannot read {LAB_FW}: {exc}", flush=True)
        _lab["failed"] = True
        return
    _lab["failed"] = False
    zones = snap.pop("zones")
    state.update(snap)
    state["system"] = {**state["system"], "hostname": os.getenv("PANOS_LAB_HOSTNAME", LAB_FW)}
    state["ha"] = {"enabled": "no"}
    return zones


def apply_lab_baseline():
    """Start the configuration from the node's zones, with no rules."""
    zones = refresh_lab(force=True)
    if zones is not None:
        state["running_config"] = {"zones": zones, "security-rules": []}
        state["candidate_config"] = deepcopy(state["running_config"])


apply_lab_baseline()
jobs = {}
next_job = 1
LOCK = threading.Lock()
JOB_COMPLETE_AFTER = 0.25


def xml_response(result=None, code=19, status="success", message=None):
    root = Element("response", status=status, code=str(code))
    result_node = SubElement(root, "result")
    if message:
        SubElement(result_node, "msg").text = message
    if result is not None:
        append_xml(result_node, result)
    return tostring(root, encoding="unicode").encode()


def append_xml(parent, value, name=None):
    if isinstance(value, Element):
        parent.append(value)
    elif isinstance(value, dict):
        for key, child in value.items():
            append_xml(parent, child, key)
    elif isinstance(value, list):
        for child in value:
            append_xml(parent, child, name or "entry")
    else:
        node = SubElement(parent, name or "value")
        node.text = str(value).lower() if isinstance(value, bool) else str(value)


def error(code, message):
    return xml_response(code=code, status="error", message=message)


# --- Configuration tree ------------------------------------------------------
# The device holds its configuration as a small Python structure. This section
# renders that structure the way PAN-OS presents it, so a client library can
# walk it with the XPath it already uses.

DEVICE_NAME = "localhost.localdomain"
VSYS_NAME = "vsys1"

# Fields a security rule holds as a list of values on a real firewall.
LIST_FIELDS = ("source", "destination", "service", "application", "source-user",
               "source-tag", "destination-tag", "from", "to", "category")


def text(node, value):
    node.text = str(value).lower() if isinstance(value, bool) else str(value)


def value_element(name, value):
    """Wrap one value. A dict becomes children, a scalar becomes text."""
    node = Element(name)
    if isinstance(value, dict):
        for key, child in value.items():
            node.append(value_element(key, child))
    elif isinstance(value, list):
        for child in value:
            node.append(entry_element(child))
    else:
        text(node, value)
    return node


def entry_element(item):
    """One <entry>. A dict with a name becomes <entry name="...">."""
    if isinstance(item, dict) and "name" in item:
        node = Element("entry", {"name": str(item["name"])})
        for key, child in item.items():
            if key != "name":
                node.append(value_element(key, child))
        return node
    node = Element("entry")
    if isinstance(item, dict):
        for key, child in item.items():
            node.append(value_element(key, child))
    else:
        text(node, item)
    return node


def rule_element(rule):
    node = Element("entry", {"name": str(rule.get("name", ""))})
    for key, value in rule.items():
        if key == "name":
            continue
        field = SubElement(node, key)
        if key in LIST_FIELDS:
            members = [m for m in str(value).split(",") if m != ""]
            for member in members:
                SubElement(field, "member").text = member
        else:
            text(field, value)
    return node


def config_tree(config):
    """The running or candidate configuration in PAN-OS shape."""
    root = Element("config")
    device = SubElement(SubElement(root, "devices"), "entry", {"name": DEVICE_NAME})
    vsys = SubElement(SubElement(device, "vsys"), "entry", {"name": VSYS_NAME})
    zones = SubElement(vsys, "zone")
    for name in config.get("zones", []):
        SubElement(zones, "entry", {"name": str(name)})
    rules = SubElement(SubElement(SubElement(vsys, "rulebase"), "security"), "rules")
    for rule in config.get("security-rules", []):
        rules.append(rule_element(rule))
    return root


def path_tokens(xpath):
    """(element name, wanted name) for each step of an XPath."""
    out = []
    for token in [t for t in xpath.strip().strip("/").split("/") if t and t != "."]:
        wanted = re.search(r"\[@name=['\"]([^'\"]+)['\"]\]", token)
        out.append((token.split("[", 1)[0], wanted.group(1) if wanted else None))
    return out


def select_config(root, xpath):
    """The node at an XPath, or None. Only /config paths are valid here."""
    tokens = path_tokens(xpath)
    if not tokens or tokens[0][0] != "config":
        return None
    node = root
    for name, wanted in tokens[1:]:
        found = None
        for child in node:
            if child.tag == name and (wanted is None or child.get("name") == wanted):
                found = child
                break
        if found is None:
            return None
        node = found
    return node



def begin_job(success=True):
    global next_job
    job_id = next_job
    next_job += 1
    # monotonic: a wall-clock step (NTP, WSL resume) must not stall or finish a job early
    jobs[str(job_id)] = {"status": "ACT", "success": success, "created": time.monotonic()}
    return job_id


def job_result(job_id):
    job = jobs.get(str(job_id))
    if not job:
        return error(7, "job not found")
    if time.monotonic() - job["created"] > JOB_COMPLETE_AFTER:
        job["status"] = "FIN"
    node = Element("job")
    text_node(node, "status", job["status"])
    if job["status"] == "FIN":
        text_node(node, "result", "OK" if job["success"] else "FAIL")
    return xml_response(node)


def current_config():
    return state.setdefault("running_config", {})


def candidate_config():
    return state.setdefault("candidate_config", deepcopy(current_config()))


def xpath_name(xpath):
    match = re.search(r"entry\[@name=['\"]([^'\"]+)['\"]\]", xpath)
    return match.group(1) if match else None


def apply_change(action, xpath, element):
    """Apply the small security-rule subset used by the lab."""
    config = candidate_config()
    if "security/rules" not in xpath:
        # ponytail: only security rules are mutable; real PAN-OS supports full XPath
        return None
    rules = config.setdefault("security-rules", [])
    name = xpath_name(xpath) or (element.attrib.get("name") if element is not None else None)
    if action == "delete":
        config["security-rules"] = [rule for rule in rules if rule.get("name") != name]
        return True
    # <source-user><member>a</member></source-user> is stored as "a"; several members as "a,b"
    values = {child.tag: ",".join(m.text or "" for m in child.findall("member")) or child.text or ""
              for child in list(element)} if element is not None else {}
    if name:
        values["name"] = name
    existing = next((rule for rule in rules if rule.get("name") == name), None)
    if existing:
        existing.update(values)
    else:
        rules.append(values)
    return True


def policy_match(query, cmd="", vsys=None):
    for field in ("from", "to", "source", "destination", "application"):
        if field not in query:
            found = re.search(fr"<{field}>([^<]*)</{field}>", cmd)
            if found:
                query[field] = [found.group(1)]
    source = query.get("from", query.get("source", [""]))[0]
    destination = query.get("to", query.get("destination", [""]))[0]
    application = query.get("application", [""])[0]
    source_ip = query.get("source", [""])[0]  # "from" is the zone, "source" the address
    for rule in candidate_config().get("security-rules", []):
        if rule.get("source") not in (source, "any", ""):
            continue
        if rule.get("destination") not in (destination, "any", ""):
            continue
        if rule.get("application") not in (application, "any", ""):
            continue
        # Who is at the source address, and what is it tagged with? (User-ID)
        if not userid_matches(rule, source_ip, vsys):
            continue
        return {"matched-rule": rule.get("name", "unnamed"), "action": rule.get("action", "deny"), "reason": "first matching rule"}
    return {"matched-rule": "interzone-default", "action": "deny", "reason": "no rule matched"}

def userid_matches(rule, ip, vsys=None):
    """Does the User-ID state for this source address satisfy the rule?

    User-ID is per vsys, as on a real firewall, so a mapping in another vsys
    does not answer for this one. source-user: the address maps to one of the
    listed users. source-tag: the address, or the user at it, holds one of the
    listed tags (the lab's stand-in for a dynamic address group)."""
    wanted_users = [u for u in rule.get("source-user", "").split(",") if u and u != "any"]
    wanted_tags = [x for x in rule.get("source-tag", "").split(",") if x]
    if not wanted_users and not wanted_tags:
        return True
    userid_expire()
    logins, tags = userid_tables(vsys)
    user = logins.get(ip, {}).get("user")
    if wanted_users and user not in wanted_users:
        return False
    held = set(tags.get(ip, {})) | set(user_tags(vsys).get(user, {}))
    return not wanted_tags or bool(held & set(wanted_tags))


# --- User-ID: IP-to-user mappings and IP tags --------------------------------
# Modeled on the PAN-OS XML API (type=user-id, <uid-message>). Mapping timeouts
# are minutes, tag timeouts are seconds, and 0 means "never expires", as on a
# real firewall. Expired entries are dropped on the next read or write.
#
# The tables are per vsys. Two tenants can hold the same address, and a
# mapping in one must not answer for the other. User tags are per vsys too.
DEFAULT_LOGIN_TIMEOUT_MIN = 45


def vsys_names():
    return state.setdefault("vsys", [VSYS_NAME])


def check_vsys(vsys):
    """The vsys name, or raise ValueError."""
    name = (vsys or VSYS_NAME).strip()
    if name not in vsys_names():
        raise ValueError("unknown vsys: %s" % name)
    return name


def vsys_or_error(query):
    """(vsys name, None) or (None, error response)."""
    try:
        return check_vsys(query.get("vsys", [""])[0]), None
    except ValueError as bad:
        return None, error(18, str(bad))


def userid_tables(vsys=None):
    name = vsys or VSYS_NAME
    logins = state.setdefault("userid_logins", {}).setdefault(name, {})
    tags = state.setdefault("userid_tags", {}).setdefault(name, {})
    return logins, tags


def user_tags(vsys=None):
    """Tags held by a user in one vsys: {user: {tag: expiry}}."""
    return state.setdefault("userid_user_tags", {}).setdefault(vsys or VSYS_NAME, {})


def userid_expire(now=None):
    now = time.time() if now is None else now
    for name in list(state.setdefault("userid_logins", {})):
        logins, tags = userid_tables(name)
        for ip in [ip for ip, e in logins.items() if e["expires"] and e["expires"] <= now]:
            del logins[ip]
        for ip in list(tags):
            tags[ip] = {tag: exp for tag, exp in tags[ip].items() if not exp or exp > now}
            if not tags[ip]:
                del tags[ip]
        utags = user_tags(name)
        for user in list(utags):
            utags[user] = {tag: exp for tag, exp in utags[user].items() if not exp or exp > now}
            if not utags[user]:
                del utags[user]


def userid_ip(value):
    """The address, or raise ValueError. PAN-OS rejects a malformed one."""
    return str(ipaddress.ip_address((value or "").strip()))


MAX_TAG_TIMEOUT = 2592000  # 30 days, the documented limit for tag timeouts


def userid_timeout(value, default, limit=None):
    """A non-negative integer, or raise ValueError. 0 means never expires."""
    n = int(default if value is None else value)
    if n < 0 or (limit is not None and n > limit):
        raise ValueError("timeout must be 0 to %s" % (limit if limit is not None else "any"))
    return n


def userid_apply(cmd, vsys=None):
    """Apply one <uid-message> to one vsys. Returns (ok, message).

    All or nothing: every entry is checked before anything changes, so a bad
    entry never leaves the tables half updated."""
    try:
        vsys_name = check_vsys(vsys)
    except ValueError as bad:
        return False, str(bad)
    try:
        root = fromstring(cmd)
    except ParseError:
        return False, "malformed uid-message"
    if root.tag != "uid-message":
        return False, "expected <uid-message>"
    payload = root.find("payload")
    if payload is None:
        return False, "uid-message has no payload"
    try:
        logins = [(e.get("name") or "", userid_ip(e.get("ip")),
                   userid_timeout(e.get("timeout"), DEFAULT_LOGIN_TIMEOUT_MIN))
                  for e in payload.findall("login/entry")]
        if any(not name for name, _, _ in logins):
            return False, "login entry needs name and ip"
        logouts = [userid_ip(e.get("ip")) for e in payload.findall("logout/entry")]
        registers = [(userid_ip(e.get("ip")),
                      [(m.text or "", userid_timeout(m.get("timeout"), 0, MAX_TAG_TIMEOUT))
                       for m in e.findall("tag/member")])
                     for e in payload.findall("register/entry")]
        unregisters = [(userid_ip(e.get("ip")), [m.text for m in e.findall("tag/member")])
                       for e in payload.findall("unregister/entry")]
        user_registers = [(e.get("user") or "",
                           [(m.text or "", userid_timeout(m.get("timeout"), 0, MAX_TAG_TIMEOUT))
                            for m in e.findall("tag/member") or e.findall("member")])
                          for e in payload.findall("register-user/entry")]
        user_unregisters = [(e.get("user") or "",
                             [m.text for m in e.findall("tag/member") or e.findall("member")])
                            for e in payload.findall("unregister-user/entry")]
        clear_users = payload.find("clear/registered-user/all") is not None
        logout_users = [e.get("name") or e.get("user") or "" for e in payload.findall("logout/entry")]
    except ValueError as error:
        return False, "invalid entry: %s" % error
    now = time.time()
    userid_expire(now)  # sweep before validating, so an expired mapping is gone
    logins_t, tags_t = userid_tables(vsys_name)
    utags = user_tags(vsys_name)
    mapped = {e["user"] for e in logins_t.values()} | {n for n, _, _ in logins}
    # A user tag needs an existing user mapping, as on a real firewall.
    for user, _ in user_registers:
        if not user or user not in mapped:
            return False, "user %s has no user mapping" % (user or "(none)")
    for user_name, ip, minutes in logins:
        logins_t[ip] = {"user": user_name, "timeout": minutes * 60, "created": now,
                        "expires": now + minutes * 60 if minutes else 0}
    for ip in logouts:
        logins_t.pop(ip, None)
    for ip, members in registers:
        for name, seconds in members:
            tags_t.setdefault(ip, {})[name] = now + seconds if seconds else 0
    for user, members in user_registers:
        for name, seconds in members:
            utags.setdefault(user, {})[name] = now + seconds if seconds else 0
    for user, names in user_unregisters:
        if names:
            for name in names:
                utags.get(user, {}).pop(name, None)
        else:
            utags.pop(user, None)
    if clear_users:
        utags.clear()
    for ip, names in unregisters:
        if names:
            for name in names:
                tags_t.get(ip, {}).pop(name, None)
        else:
            tags_t.pop(ip, None)
    userid_expire(now)
    return True, "User-ID update applied to %s" % vsys_name


def text_node(parent, name, value):
    SubElement(parent, name).text = str(value)


def userid_mappings(vsys=None):
    name = check_vsys(vsys)
    userid_expire()
    now = time.time()
    result = Element("mappings")
    for ip, e in sorted(userid_tables(name)[0].items()):
        entry = SubElement(result, "entry")
        for key, value in (("ip", ip), ("vsys", name), ("type", "XMLAPI"), ("user", e["user"]),
                           ("idle_timeout", int(e["expires"] - now) if e["expires"] else 0),
                           ("timeout", e["timeout"])):
            text_node(entry, key, value)
    text_node(result, "count", len(result.findall("entry")))
    return list(result)


def userid_registered(vsys=None):
    name = check_vsys(vsys)
    userid_expire()
    now = time.time()
    result = Element("registered")
    for ip, named in sorted(userid_tables(name)[1].items()):
        entry = SubElement(result, "entry")
        text_node(entry, "ip", ip)
        text_node(entry, "vsys", name)
        tag = SubElement(entry, "tag")
        for tag_name, exp in named.items():
            member = SubElement(tag, "member")
            member.text = tag_name
            member.set("timeout", str(int(exp - now) if exp else 0))
    text_node(result, "count", len(result.findall("entry")))
    return list(result)


MAX_BODY = 16 * 1024 * 1024  # 100,000 login entries are about 6 MB


def interface_entries():
    """<interfaces><entry name="ethernet1/1">...</entry></interfaces>"""
    root = Element("interfaces")
    for name, data in sorted(state.get("interfaces", {}).items()):
        entry = SubElement(root, "entry", {"name": name})
        if isinstance(data, dict):
            for key, value in data.items():
                entry.append(value_element(key, value))
    return root


def route_entries():
    """<virtual-router><entry name="default"><routing-table>...</entry>"""
    root = Element("virtual-router")
    for vr_name, data in sorted(state.get("virtual-routers", {}).items()):
        vr = SubElement(root, "entry", {"name": str(vr_name)})
        table = SubElement(vr, "routing-table")
        for route in (data or {}).get("routes", []):
            entry = SubElement(table, "entry")
            fields = (("destination", route.get("destination")),
                      ("nexthop", route.get("nexthop", route.get("next-hop"))),
                      ("interface", route.get("interface")),
                      ("flags", route.get("flags")),
                      ("metric", route.get("metric")))
            for key, value in fields:
                if value is not None:
                    text_node(entry, key, value)
    return root


def bgp_entries(cmd=""):
    """Peers as `show routing protocol bgp peer` returns them.

    Real PAN-OS lists `<entry peer="name" vr="default">` with the session state.
    Without a lab mirror no BGP is configured, so the answer is an empty branch.
    The element names are from the author's memory: check them on a real
    firewall (TRAINING.md). The peer name here is `peer-<address>`.
    """
    bgp = state.get("bgp")
    if not bgp:
        return Element("bgp")
    # The CLI reference gives `show routing protocol bgp peer peer-name <n>
    # virtual-router <vr>`. PAN-OS XML nests each CLI word as an element.
    want_vr = re.search(r"<virtual-router>([^<]+)</virtual-router>", cmd)
    want_peer = re.search(r"<peer-name>([^<]+)</peer-name>", cmd)
    root = Element("bgp")
    for vr, data in sorted(bgp.items()):
        if want_vr and want_vr.group(1) != vr:
            continue
        for peer in data.get("peers", []):
            name = f"peer-{peer['peer-address']}"
            if want_peer and want_peer.group(1) != name:
                continue
            entry = SubElement(root, "entry", {"peer": name, "vr": vr})
            for key, value in (("local-as", data.get("local-as")), ("router-id", data.get("router-id")), *peer.items()):
                if value is not None:
                    text_node(entry, key, value)
    return root


def session_entries():
    return value_element("session", state.get("sessions", {}))


def license_entries():
    root = Element("licenses")
    for name, data in sorted(state.get("licenses", {}).items()):
        entry = SubElement(root, "entry", {"name": str(name)})
        if isinstance(data, dict):
            for key, value in data.items():
                entry.append(value_element(key, value))
    return root


def vpn_entries():
    root = Element("vpn")
    for tunnel in state.get("vpn", []):
        root.append(entry_element(tunnel))
    return root


def log_entries():
    root = Element("logs")
    for record in state.get("logs", []):
        root.append(entry_element(record))
    return root


def policy_match_xml(match):
    root = Element("rules")
    entry = SubElement(root, "entry", {"name": str(match["matched-rule"])})
    text_node(entry, "action", match["action"])
    text_node(entry, "reason", match["reason"])
    return root


class Handler(BaseHTTPRequestHandler):
    server_version = "PANOS-Lab/0.1"
    timeout = 30  # drop a client that stalls mid-request instead of holding a thread forever

    def log_message(self, fmt, *args):
        if os.getenv("PANOS_ACCESS_LOG"):
            super().log_message(fmt, *args)

    def send_xml(self, body, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, value, status=200):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, body):
        body = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def dashboard(self):
        return """<!doctype html><meta name=viewport content="width=device-width"><title>PAN-OS Lab</title>
<style>body{font:16px system-ui;max-width:1000px;margin:2rem auto;padding:0 1rem;background:#f6f7f9;color:#17202a}section{background:white;padding:1rem;margin:1rem 0;border:1px solid #ddd;border-radius:8px}button{margin:.25rem;padding:.45rem .7rem}pre{background:#111;color:#d7f9d7;padding:1rem;overflow:auto;white-space:pre-wrap}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:.5rem}.card{background:#eef3f8;padding:.7rem;border-radius:5px}.muted{color:#667}</style>
<h1>PAN-OS Lab Emulator</h1><p class=muted>Fake management plane for training. It does not forward packets.</p>
<section><h2>Device status</h2><div id=status class=grid></div><button onclick="refresh()">Refresh</button></section>
<section><h2>Scenarios</h2><p class=muted>Change the device condition, then refresh the status view.</p><div id=scenarios></div></section>
<section><h2>Operational state</h2><div id=ops></div></section>
<section><h2>Configuration</h2><p>Candidate changes stay separate until commit.</p><button onclick="showConfig()">Show config</button> <button onclick="commit()">Commit candidate</button><pre id=config></pre></section>
<section><h2>Policy match</h2><input id=from placeholder="source zone" value="trust"> <input id=to placeholder="destination zone" value="untrust"> <input id=app placeholder="application" value="ssl"> <button onclick="matchPolicy()">Test</button><pre id=match></pre></section>
<script>
const q=(u,o={})=>fetch(u,o).then(r=>r.text());
const api=(cmd)=>q('/api?type=op&cmd='+encodeURIComponent(cmd));
const card=(name,value)=>'<div class=card><b>'+name+'</b><br>'+value+'</div>';
async function refresh(){
  const v=await q('/api?type=version'); const s=await api('<show><system><info></info></system></show>'); const h=await api('<show><high-availability></high-availability></show>');
  document.querySelector('#status').innerHTML=card('Version',v.match(/<version>(.*?)<\\/version>/)?.[1]||'?')+card('Hostname',s.match(/<hostname>(.*?)<\\/hostname>/)?.[1]||'?')+card('HA state',h.match(/<local-state>(.*?)<\\/local-state>/)?.[1]||'?')+card('Peer',h.match(/<peer-state>(.*?)<\\/peer-state>/)?.[1]||'?');
  document.querySelector('#ops').innerHTML='<button onclick="op(\\'<show><interface></interface></show>\\')">Interfaces</button><button onclick="op(\\'<show><routing></routing></show>\\')">Routes</button><button onclick="op(\\'<show><vpn></vpn></show>\\')">VPN</button><button onclick="op(\\'<show><session></session></show>\\')">Sessions</button><button onclick="op(\\'<show><license></license></show>\\')">Licenses</button><button onclick="op(\\'<show><system><info></info></system></show>\\')">System</button><pre id=output></pre>';
}
async function op(cmd){document.querySelector('#output').textContent=await api(cmd)}
async function showConfig(){document.querySelector('#config').textContent=await q('/api?type=config&action=show')}
async function commit(){document.querySelector('#config').textContent=await q('/api?type=commit',{method:'POST'})}
async function matchPolicy(){let u='/api?type=op&cmd='+encodeURIComponent('<test><security-policy-match><from>'+from.value+'</from><to>'+to.value+'</to><application>'+app.value+'</application></security-policy-match></test>');document.querySelector('#match').textContent=await q(u)}
async function scenario(name){await q('/scenario/'+name,{method:'POST'});refresh()}
document.querySelector('#scenarios').innerHTML=['healthy','ha-out-of-sync','tunnel-down','license-expiring','high-sessions','commit-failure'].map(x=>'<button onclick="scenario(\\''+x+'\\')">'+x+'</button>').join('');refresh();
</script>"""

    def authorized(self, query):
        if not API_KEY or query.get("type") == ["keygen"]:
            return True  # keygen must work before a client has a key
        header_key = self.headers.get("X-PAN-KEY", "")
        query_key = query.get("key", [""])[0]
        return hmac.compare_digest(header_key, API_KEY) or hmac.compare_digest(query_key, API_KEY)

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/":
            self.send_html(self.dashboard())
            return
        if parsed.path == "/health":
            self.send_xml(xml_response({"status": "up"}))
            return
        if not self.authorized(query):
            self.send_xml(error(16, "unauthorized"), 403)
            return
        if parsed.path.startswith("/api"):
            with LOCK:
                self.send_xml(self.api(query))
            return
        if parsed.path.startswith("/restapi/"):
            self.send_json(self.rest_api(parsed.path, query))
            return
        self.send_xml(error(1, "unknown command"), 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = -1
        if length < 0:
            self.close_connection = True
            self.send_xml(error(18, "bad Content-Length"), 400)
            return
        if length > MAX_BODY:
            self.close_connection = True  # the body is never read
            self.send_xml(error(18, "request body too large"), 413)
            return
        try:
            body = self.rfile.read(length).decode()
        except UnicodeDecodeError:
            self.send_xml(error(18, "request body is not UTF-8"), 400)
            return
        if body and not body.lstrip().startswith("<"):
            # form-encoded body (what requests/curl -d send): merge its fields
            for field, values in parse_qs(body).items():
                query.setdefault(field, values)
            body = ""
        if not self.authorized(query):
            self.send_xml(error(16, "unauthorized"), 403)
            return
        if parsed.path.startswith("/scenario/"):
            name = parsed.path.rsplit("/", 1)[-1]
            path = (SCENARIOS / f"{name}.json").resolve()
            if SCENARIOS.resolve() != path.parent or not path.exists():
                self.send_xml(error(7, "scenario not found"), 404)
                return
            with LOCK:
                switch_scenario(path)
            self.send_xml(xml_response({"scenario": name}))
            return
        if parsed.path.startswith("/api"):
            with LOCK:
                self.send_xml(self.api(query, body))
            return
        self.send_xml(error(1, "unknown command"), 404)

    def api(self, query, body=""):
        kind = query.get("type", [""])[0]
        action = query.get("action", [""])[0]
        if kind == "version":
            return xml_response({"version": state["system"]["sw-version"]})
        if kind == "op":
            cmd = unquote(query.get("cmd", [""])[0])
            match = re.search(r"<id>(\d+)</id>", cmd)
            if match:
                return job_result(match.group(1))
            if "ip-user-mapping" in cmd:
                vsys, failure = vsys_or_error(query)
                return failure or xml_response(userid_mappings(vsys))
            if "registered-ip" in cmd:
                vsys, failure = vsys_or_error(query)
                return failure or xml_response(userid_registered(vsys))
            if any(w in cmd for w in ("bgp", "session", "interface", "route", "routing")):
                refresh_lab()
            if "high-availability" in cmd:
                return xml_response(value_element("high-availability", state.get("ha", {})))
            if "bgp" in cmd:
                if state.get("bgp") and re.search(r"<(summary|peer-group|policy|loc-rib|rib-out|loc-rib-detail|rib-out-detail)\b", cmd):
                    return error(1, "this BGP command is not modeled")
                return xml_response(bgp_entries(cmd))
            if "vpn" in cmd:
                return xml_response(vpn_entries())
            if "session" in cmd:
                return xml_response(session_entries())
            if "interface" in cmd:
                return xml_response(interface_entries())
            if "routing" in cmd or "route" in cmd:
                return xml_response(route_entries())
            if "license" in cmd:
                return xml_response(license_entries())
            if "security-policy-match" in cmd or (not cmd and any(f in query for f in ("from", "to", "application"))):
                vsys, failure = vsys_or_error(query)
                return failure or xml_response(policy_match_xml(policy_match(query, cmd, vsys)))
            if "system" in cmd:
                return xml_response(value_element("system", state["system"]))
            return error(1, "unknown operational command")
        if kind == "log":
            return xml_response(log_entries())
        if kind == "keygen":
            return xml_response({"key": API_KEY or "lab-key"})
        if kind == "user-id":
            cmd = query.get("cmd", [""])[0] or body
            if not cmd.strip():
                return xml_response({"user-id": state.get("user-id", [])})
            ok, message = userid_apply(cmd, query.get("vsys", [""])[0])
            return xml_response({"msg": message}) if ok else error(18, message)
        if kind == "config":
            if action in ("show", "get"):
                # Real PAN-OS: show is the running configuration, get is the
                # candidate one. Both honour xpath under /config.
                config = current_config() if action == "show" else candidate_config()
                xpath = query.get("xpath", [""])[0]
                if not xpath:
                    return xml_response(config_tree(config))
                tokens = path_tokens(xpath)
                if not tokens or tokens[0][0] != "config":
                    return error(6, "unsupported xpath in this lab: %s" % xpath)
                node = select_config(config_tree(config), xpath)
                # A path under /config that holds nothing is empty, not an
                # error: the node exists and has no children yet.
                return xml_response(node if node is not None else Element("config"))
            if action == "validate":
                rules = candidate_config().get("security-rules", [])
                names = [rule.get("name") for rule in rules]
                if len(names) != len(set(names)):
                    return error(12, "duplicate security rule name")
                return xml_response({"msg": "validation passed"})
            if action in ("set", "edit", "delete"):
                xpath = query.get("xpath", [""])[0]
                element_text = body or query.get("element", [""])[0]
                try:
                    from xml.etree.ElementTree import fromstring
                    element = fromstring(element_text) if element_text else None
                except Exception:
                    return error(18, "malformed command")
                applied = apply_change(action, xpath, element)
                if applied is None:
                    return error(6, f"unsupported xpath in this lab: {xpath}")
                state.setdefault("candidate_changes", []).append({"action": action, "xpath": xpath})
                return xml_response({"msg": "configuration updated"})
            return error(17, "invalid configuration action")
        if kind == "commit":
            success = state.get("commit", {}).get("result", "OK") == "OK"
            job_id = begin_job(success)
            if success:
                state["running_config"] = deepcopy(candidate_config())
                state["last_commit"] = {"changes": state.get("candidate_changes", []), "time": time.time()}
                state["candidate_changes"] = []
                state["candidate_config"] = deepcopy(state["running_config"])
            return xml_response({"job": job_id, "msg": f"Commit job enqueued with jobid {job_id}"})
        return error(1, "unknown command")

    def rest_api(self, path, query):
        # /restapi/v11.0/<Group>/<Resource> per the PAN-OS REST API doc
        parts = [p for p in path.split("/") if p]
        resource = parts[-1] if len(parts) >= 2 else ""
        data = {
            "SecurityRules": candidate_config().get("security-rules", []),
            "Zones": current_config().get("zones", []),
            "Addresses": state.get("addresses", []),
            "Services": state.get("services", []),
        }.get(resource, [])
        return {"resource": resource, "data": data}


class Server(ThreadingHTTPServer):
    # The default listen backlog is 5, so a burst of clients (a NAC and a
    # monitor polling together) got "connection reset by peer" while one
    # request held the lock.
    request_queue_size = 128


def main():
    host = os.getenv("PANOS_HOST", "0.0.0.0")
    port = int(os.getenv("PANOS_PORT", "8080"))
    # A multi-tenant lab needs a second vsys. Comma separated, vsys1 always present.
    names = [n.strip() for n in os.getenv("PANOS_VSYS", VSYS_NAME).split(",") if n.strip()]
    if VSYS_NAME not in names:
        names.insert(0, VSYS_NAME)
    state["vsys"] = names
    print(f"PAN-OS lab emulator listening on {host}:{port} (vsys: {', '.join(names)})", flush=True)
    Server((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
