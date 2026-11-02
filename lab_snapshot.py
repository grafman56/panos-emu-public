"""Read a running Containerlab firewall node and return emulator state.

Set PANOS_LAB_FW to the container name (for example
clab-evpn-vxlan-campus-fw-a) and the emulator shows that node's interfaces,
zones, routes, BGP peers and session count, instead of the sample data.

The node must run FRR (vtysh) and keep its zones in an nftables table named
`zones`, with one set per zone called `<zone>_ifaces`. Standard library only.
It needs the `docker` command and permission to use it.
"""
import json
import re
import subprocess

ZONE_ALIASES = {"inet": "internet"}  # the lab names this set "inet"


def _run(container, *cmd):
    out = subprocess.run(["docker", "exec", container, *cmd], capture_output=True, text=True, timeout=10)
    if out.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {out.stderr.strip()[:200]}")
    return out.stdout


def _json(container, *cmd):
    return json.loads(_run(container, *cmd))


def _zones(container):
    """{zone: [interface, ...]} from the `zones` nftables table."""
    zones = {}
    for item in _json(container, "nft", "-j", "list", "sets")["nftables"]:
        s = item.get("set")
        if s and s.get("table") == "zones" and s["name"].endswith("_ifaces"):
            name = s["name"][: -len("_ifaces")]
            zones[ZONE_ALIASES.get(name, name)] = [e for e in s.get("elem", []) if isinstance(e, str)]
    return zones


def _port(name):
    """eth1 -> ethernet1/1, eth1.30 -> ethernet1/1.30. None for eth0 and other devices."""
    m = re.fullmatch(r"eth(\d+)(?:\.(\d+))?", name)
    if not m or m.group(1) == "0":
        return None
    return f"ethernet1/{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else "")


def _interfaces(container, zones):
    zone_of = {i: z for z, members in zones.items() for i in members}
    result = {}
    for link in _json(container, "ip", "-j", "addr"):
        base = link["ifname"].split("@")[0]
        port = _port(base)
        if not port:
            continue
        entry = {"state": "up" if link.get("operstate") in ("UP", "UNKNOWN") else "down",
                 "virtual-router": link.get("master", "default")}
        addrs = [f"{a['local']}/{a['prefixlen']}" for a in link.get("addr_info", []) if a["family"] == "inet"]
        if addrs:
            entry["ip"] = addrs[0]
        if base in zone_of:
            entry["zone"] = zone_of[base]
        result[port] = entry
    return result


FLAGS = {"connected": "A C", "static": "A S", "ospf": "A O", "bgp": "A B"}


def _routes(container):
    routers = {}
    for vrf, table in _json(container, "vtysh", "-c", "show ip route vrf all json").items():
        routes = []
        for prefix, entries in table.items():
            for r in entries:
                flags = FLAGS.get(r.get("protocol"))
                if not flags or not r.get("selected"):
                    continue  # skip local/kernel routes and routes that lost selection
                for hop in r.get("nexthops", []) or [{}]:
                    route = {"destination": prefix, "flags": flags, "metric": r.get("metric", 0)}
                    if hop.get("ip"):
                        route["nexthop"] = hop["ip"]
                    if hop.get("interfaceName"):
                        route["interface"] = _port(hop["interfaceName"].split("@")[0]) or hop["interfaceName"]
                    routes.append(route)
        routers[vrf] = {"routes": sorted(routes, key=lambda x: x["destination"])}
    return routers


def _bgp(container):
    out = {}
    for vrf, families in _json(container, "vtysh", "-c", "show bgp vrf all summary json").items():
        fam = families.get("ipv4Unicast") or {}
        peers = [{"peer-address": ip, "remote-as": p["remoteAs"], "status": p["state"],
                  "status-duration": p.get("peerUptimeMsec", 0) // 1000,
                  "msg-total-in": p.get("msgRcvd", 0), "msg-total-out": p.get("msgSent", 0),
                  "prefixes-received": p.get("pfxRcd", 0), "prefixes-sent": p.get("pfxSnt", 0)}
                 for ip, p in sorted(fam.get("peers", {}).items())]
        out[vrf] = {"router-id": fam.get("routerId"), "local-as": fam.get("as"), "peers": peers}
    return out


def _sessions(container):
    try:
        active = int(_run(container, "conntrack", "-C"))
        maximum = int(_run(container, "cat", "/proc/sys/net/netfilter/nf_conntrack_max"))
    except (RuntimeError, ValueError):
        return None
    return {"active": active, "maximum": maximum, "utilization": round(100 * active / maximum, 2)}


def snapshot(container):
    zones = _zones(container)
    snap = {"zones": sorted(zones), "interfaces": _interfaces(container, zones),
            "virtual-routers": _routes(container), "bgp": _bgp(container)}
    sessions = _sessions(container)
    if sessions:
        snap["sessions"] = sessions
    return snap
