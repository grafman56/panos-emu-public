# PAN-OS Lab Emulator

A small fake PAN-OS management endpoint for Containerlab exercises. It answers
the XML API the way a firewall does, so an automation script, a client library
or an Ansible playbook can be tested without a firewall.

It does not forward packets, and it has no dataplane or App-ID. It answers
management requests and keeps state.

## What you can practise with it

- Read configuration and operational state with the PAN-OS XML API
- Change candidate configuration, commit it, and poll the job
- Test a security rule against the candidate, with and without a User-ID mapping
- Publish IP-to-user mappings and tags, then check that a rule matches on them
- Switch the device to a failure condition and watch a script react

## Requirements

- Python 3.12, the version in the Docker image. Older 3.x probably works and is
  untested.
- Docker, if you want to run it as a container
- Nothing else. The emulator uses the standard library only.

## Run it

```sh
python3 panos_emulator.py
```

It prints one line and keeps running:

```text
PAN-OS lab emulator listening on 0.0.0.0:8080 (vsys: vsys1)
```

In a second terminal, ask for the software version:

```sh
curl -s 'http://127.0.0.1:8080/api?type=version'
```

```xml
<response status="success" code="19"><result><version>11.1.0</version></result></response>
```

The management API answers on `/api`. A health check for containers answers on
`/health`:

```sh
curl -s http://127.0.0.1:8080/health
```

```xml
<response status="success" code="19"><result><status>up</status></result></response>
```

Open `http://127.0.0.1:8080/` in a browser for a live status page. It shows the
version, hostname and HA state, buttons that query interfaces, routes, VPN,
sessions, licences and system, a Show config and Commit button, a policy match
form, and one button per scenario.

### Settings

| Variable | Default | Meaning |
|---|---|---|
| `PANOS_PORT` | `8080` | Listen port |
| `PANOS_HOST` | `0.0.0.0` | Listen address |
| `PANOS_DATA` | `data/default.json` | Initial device state |
| `PANOS_VSYS` | `vsys1` | Comma separated vsys list, for a second tenant |
| `PANOS_API_KEY` | empty | Set it to require the `X-PAN-KEY` header |
| `PANOS_LAB_FW` | empty | Container name of a lab firewall to mirror |
| `PANOS_LAB_HOSTNAME` | the container name | Hostname to report in mirror mode |

Authentication is off by default, so a lab needs no keys.

## Read configuration and state

`action=show` returns the running configuration. `action=get` returns the
candidate. Both take an `xpath`, which selects a subtree:

```sh
curl -s -G http://127.0.0.1:8080/api \
  --data-urlencode 'type=config' --data-urlencode 'action=show' \
  --data-urlencode "xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules"
```

```xml
<response status="success" code="19"><result><rules><entry name="allow-dns"><source><member>trust</member></source><destination><member>untrust</member></destination><application><member>dns</member></application><action>allow</action></entry></rules></result></response>
```

Leave the `xpath` out to read the whole configuration. A path outside `/config`
is error 6. A path under `/config` that holds nothing returns success with an
empty node.

Operational reads are keyed, so a parser can find entries by name:

| Query | Shape |
|---|---|
| `show interface` | `<interfaces><entry name="ethernet1/1"><state/><zone/><link/></entry></interfaces>` |
| `show routing route` | `<virtual-router><entry name="default"><routing-table><entry><destination/><nexthop/></entry></routing-table></entry></virtual-router>` |
| `show license` | `<licenses><entry name="threat-prevention"><status/><days-remaining/></entry></licenses>` |
| `show session` | `<session><active/><maximum/><utilization/></session>` |
| `show system info` | `<system><hostname/><serial/><sw-version/></system>` |
| `show routing protocol bgp` | `<bgp/>`, empty: this lab configures no BGP |
| `test security-policy-match` | `<rules><entry name="allow-dns"><action/><reason/></entry></rules>` |

## Change configuration, then commit

Configuration changes go to the candidate. Commit copies the candidate to the
running configuration. The only mutable object in this lab is the security
rulebase.

Add a rule:

```sh
curl -s -X POST \
  --data-urlencode 'type=config' --data-urlencode 'action=set' \
  --data-urlencode "xpath=security/rules/entry[@name='allow-dns']" \
  --data-urlencode 'element=<entry><source>trust</source><destination>untrust</destination><application>dns</application><action>allow</action></entry>' \
  http://127.0.0.1:8080/api
```

```xml
<response status="success" code="19"><result><msg>configuration updated</msg></result></response>
```

Test a rule before you commit it. Matching reads the candidate:

```sh
curl -s -G http://127.0.0.1:8080/api \
  --data-urlencode 'type=op' --data-urlencode 'from=trust' \
  --data-urlencode 'to=untrust' --data-urlencode 'application=dns'
```

```xml
<response status="success" code="19"><result><rules><entry name="allow-dns"><action>allow</action><reason>first matching rule</reason></entry></rules></result></response>
```

A rule that keys on a user or a tag returns `interzone-default` until User-ID
knows who is at the source address. See the next section.

Commit, then poll the job:

```sh
curl -s -X POST --data-urlencode 'type=commit' http://127.0.0.1:8080/api
curl -s -G http://127.0.0.1:8080/api \
  --data-urlencode 'type=op' --data-urlencode 'cmd=<show><jobs><id>1</id></jobs></show>'
```

```xml
<response status="success" code="19"><result><job><status>FIN</status><result>OK</result></job></result></response>
```

The job finishes about a quarter of a second after the commit, so a poll loop
sees `ACT` at least once.

## User-ID

A firewall can learn which user holds which address. The emulator holds two
tables for that: IP-to-user mappings, and tags on an address or on a user. A
security rule can match on `source-user` or `source-tag`.

Publish one mapping:

```sh
curl -s -X POST http://127.0.0.1:8080/api \
  --data-urlencode 'type=user-id' \
  --data-urlencode 'cmd=<uid-message><version>1.0</version><type>update</type><payload><login><entry name="jsmith@campus.edu" ip="10.10.10.100"/></login></payload></uid-message>'
```

```xml
<response status="success" code="19"><result><msg>User-ID update applied to vsys1</msg></result></response>
```

Read it back:

```sh
curl -s -G http://127.0.0.1:8080/api \
  --data-urlencode 'type=op' \
  --data-urlencode 'cmd=<show><user><ip-user-mapping><all/></ip-user-mapping></user></show>'
```

```xml
<response status="success" code="19"><result><entry><ip>10.10.10.100</ip><vsys>vsys1</vsys><type>XMLAPI</type><user>jsmith@campus.edu</user><idle_timeout>2699</idle_timeout><timeout>2700</timeout></entry><count>1</count></result></response>
```

The payload types are `login`, `logout`, `register`, `unregister`,
`register-user`, `unregister-user` and `clear`. A login times out after 45
minutes by default. A timeout of `0` means never, and that is the default for a
tag. A tag timeout cannot exceed 30 days.

Mappings are per vsys, as on a real firewall. Two tenants can hold the same
address, and a policy check in one vsys does not see the other. Pass `vsys=` on
any User-ID or policy request; the default is `vsys1`.

```sh
# start with a second tenant
PANOS_VSYS=vsys1,vsys2 python3 panos_emulator.py

# read the table that belongs to vsys2
curl -s -G http://127.0.0.1:8080/api \
  --data-urlencode 'type=op' --data-urlencode 'vsys=vsys2' \
  --data-urlencode 'cmd=<show><user><ip-user-mapping><all/></ip-user-mapping></user></show>'
```

An unknown vsys is error 18. User tags are per vsys too, so a tag registered for
a user in one vsys does not apply to that user in another.

`TRAINING.md` has the exercises. It also lists what to re-check on a real
firewall, because some of this is lab behaviour, not documented PAN-OS
behaviour.

## Change the device condition

A scenario is one JSON file under `scenarios/`. It changes the condition, so
interfaces and routes stay as they were, and published User-ID mappings and tags
stay too. Configuration does not: the scenario brings its own running
configuration, and any uncommitted candidate changes are dropped.

```sh
curl -s -X POST http://127.0.0.1:8080/scenario/ha-out-of-sync
curl -s -X POST http://127.0.0.1:8080/scenario/healthy   # back to normal
```

```text
healthy  ha-out-of-sync  tunnel-down  license-expiring  high-sessions  commit-failure
```

Add a file to `scenarios/` to create another condition. Point `PANOS_DATA` at a
different fixture to change the starting state.

## Mirror a lab firewall

By default the emulator shows sample data. To make it show a real Containerlab
firewall instead, point it at that node:

```sh
PANOS_LAB_FW=clab-evpn-vxlan-campus-fw-a PANOS_LAB_HOSTNAME=fw-a python3 panos_emulator.py
```

It then reads the node every few seconds and shows what the node has:

| You ask for | You get |
|---|---|
| `show interface` | The node's ports as `ethernet1/N`, with address, zone and virtual router |
| `show routing route` | The node's routes, one virtual router per VRF, with `A C`, `A O` or `A B` flags |
| `show routing protocol bgp peer` | Each BGP session, with its state, AS number and prefix counts |
| `show session` | The node's connection count |
| Zones in the configuration | The zones in the node's `zones` nftables table |

If you shut a BGP session on the node, the peer shows `Idle` within a few seconds.
If the node is down, the emulator keeps the last copy and prints one warning.

What you need:

- The `docker` command, and permission to use it, on the machine that runs the emulator.
- A node that runs FRR and keeps its zones in an nftables table named `zones`, with one
  set per zone called `<zone>_ifaces`. The campus lab firewalls do.

What it does not mirror: security rules (the rulebase starts empty and you manage it
through the API), NAT, and anything the node does not have. Switching scenario resets
the configuration to the node's zones with no rules.

The BGP element names and the `A B` route flags come from memory of real PAN-OS output.
See "Check these on a real firewall" in `TRAINING.md`.

## Use it with the campus lab

The [two-site campus lab](https://github.com/grafman56/containerlab-labs-public/tree/main/evpn-vxlan-campus)
publishes users and role tags to this emulator and checks them. Start the
emulator in mirror mode (see above), then follow the campus README. Its
demo script expects the emulator on `127.0.0.1:8080`.

## Tests

```sh
python3 -m pip install -r requirements-dev.txt
python3 -m pytest tests/ -q
```

`requirements-dev.txt` installs `pytest` and `pan-python`. Only `pytest` is
needed to run the suite. One test in `tests/test_xml_contract.py` reads the
configuration through `pan-python` and skips when the package is missing, so
install both to run every check.

## Run with Docker

```sh
docker build -t panos-emulator .
docker run --rm -p 8080:8080 panos-emulator
```

Or with Compose:

```sh
docker compose up --build -d
docker compose down
```

The image has a health check on `/health`.

## Run in Containerlab

`containerlab.yml` deploys one `panos` node and one Alpine client on a link:

```sh
docker build -t panos-emulator:latest .
containerlab deploy -t containerlab.yml
docker exec -it clab-panos-lab-client sh   # then: wget -qO- http://panos:8080/health
containerlab destroy -t containerlab.yml
```

The `panos` node publishes port 8080 on the host, so the API and the browser page
stay reachable from outside the lab. Stop any local emulator first, or the
deploy fails because the port is taken.

## Files

| File | Contents |
|---|---|
| `panos_emulator.py` | The whole server |
| `lab_snapshot.py` | Reads a lab firewall node for mirror mode |
| `data/default.json` | Starting device state |
| `scenarios/*.json` | Device conditions you can switch to |
| `ARCHITECTURE.md` | How state and responses are built |
| `TRAINING.md` | Exercises and the fidelity notes |

`ARCHITECTURE.md` and `TRAINING.md` define what the emulator does.
