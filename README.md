# PAN-OS Lab Emulator

Small, fake, data-driven PAN-OS management endpoint for Containerlab training. It does not forward packets and is not a firewall.

## Run locally

```sh
python3 panos_emulator.py
curl 'http://127.0.0.1:8080/api?type=op&cmd=%3Cshow%3E%3Csystem%3E%3Cinfo%3E%3C%2Finfo%3E%3C%2Fsystem%3E%3C%2Fshow%3E'
```

## Run with Docker

```sh
docker build -t panos-emulator .
docker run --rm -p 8080:8080 panos-emulator
```

Or use Docker Compose:

```sh
docker compose up --build -d
```

Open `http://127.0.0.1:8080/` for the browser landing page. Authentication is off by default for easy lab use. Set `PANOS_API_KEY` to require the `X-PAN-KEY` header when testing authenticated clients.

## User-ID

The emulator holds IP-to-user mappings and IP tags (`type=user-id` with `<uid-message>`, `show user ip-user-mapping`, `show object registered-ip`). Rules can match on `source-user` and `source-tag`. See `TRAINING.md`, which also lists what to re-verify on a real firewall.

Mappings are per vsys, as on a real firewall. Two tenants can hold the same address, and a policy check in one vsys does not see the other. Pass the vsys as a query parameter; the default is `vsys1`.

```sh
# a second tenant vsys exists in this process
PANOS_VSYS=vsys1,vsys2 python3 panos_emulator.py

curl -G http://127.0.0.1:8080/api \
  --data-urlencode 'type=op' --data-urlencode 'vsys=vsys2' \
  --data-urlencode 'cmd=<show><user><ip-user-mapping><all/></ip-user-mapping></user></show>'
```

An unknown vsys is error 18 on write and on read. User tags are per vsys too: a tag set on a user in `vsys2` does not apply to that user in `vsys1`.

## Change a scenario

```sh
curl -X POST http://127.0.0.1:8080/scenario/ha-out-of-sync
curl -X POST http://127.0.0.1:8080/scenario/healthy
```

Add a JSON file under `scenarios/` to create another deterministic device condition.

## Candidate configuration and policy matching

Configuration changes stay in candidate state until commit. The small supported training subset is security rules.

Configuration reads follow PAN-OS: `action=show` returns the running configuration, `action=get` returns the candidate. Both accept an `xpath` under `/config` and return the subtree in the real device shape, so a client library can walk it:

```sh
# the whole running configuration
curl 'http://127.0.0.1:8080/api?type=config&action=show'

# just the security rulebase
curl -G http://127.0.0.1:8080/api \
  --data-urlencode 'type=config' --data-urlencode 'action=show' \
  --data-urlencode "xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules"

# the candidate rulebase, before commit
curl -G http://127.0.0.1:8080/api \
  --data-urlencode 'type=config' --data-urlencode 'action=get' \
  --data-urlencode "xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules"
```

A path outside `/config` returns error 6. A path under `/config` that holds nothing returns success with an empty node.

Write a rule with the short XPath used by the exercises, or with the full path a client sends:

```sh
curl -X POST \
  --data-urlencode 'type=config' --data-urlencode 'action=set' \
  --data-urlencode "xpath=security/rules/entry[@name='allow-dns']" \
  --data-urlencode 'element=<entry><source>trust</source><destination>untrust</destination><application>dns</application><action>allow</action></entry>' \
  http://127.0.0.1:8080/api
```

Use `type=config&action=validate`, then `type=commit`, and poll the returned job ID. Job status is nested the way a client expects:

```xml
<result><job><status>FIN</status><result>OK</result></job></result>
```

Policy match works two ways: a `<test><security-policy-match>` XML command, or bare query params:

```sh
curl 'http://127.0.0.1:8080/api?type=op&from=trust&to=untrust&application=dns'
```

Matching is against the **candidate** config, so you can test a rule before committing it.
Only security rules are mutable in this lab; other xpaths return error 6.

Scenarios are JSON files. Add one without changing Python code. Set `PANOS_DATA` to use a different initial fixture. Set `PANOS_API_KEY` only when you want to test authentication.

## Training loop

1. Query operational state.
2. Change candidate configuration with `type=config`.
3. Commit and capture the returned job ID.
4. Poll `type=op` until the job is `FIN`.
5. Switch to a failure scenario and investigate the changed device state.

See [TRAINING.md](TRAINING.md) for exercises.

The XML API response shape follows PAN-OS concepts: status, numeric code, result, candidate changes, commits, and asynchronous jobs. It is intentionally incomplete. Add an endpoint only when a training exercise needs it.

Operational reads are keyed, not flat, so a parser can use them:

| Query | Shape |
|---|---|
| `show interface` | `<interfaces><entry name="ethernet1/1"><state/><zone/><link/></entry>` |
| `show routing route` | `<virtual-router><entry name="default"><routing-table><entry><destination/><nexthop/></entry>` |
| `show license` | `<licenses><entry name="threat-prevention"><status/><days-remaining/>` |
| `show session` | `<session><active/><maximum/><utilization/>` |
| `show system info` | `<system><hostname/><serial/><sw-version/>` |
| `show routing protocol bgp` | `<bgp/>`, empty: no BGP is configured in this lab |
| `test security-policy-match` | `<rules><entry name="allow-web"><action/><reason/>` |

## Tests

`pytest` is the only development dependency:

```sh
python3 -m pip install -r requirements-dev.txt
python3 -m pytest tests/ -q
```

`tests/test_xml_contract.py` holds the shape a client library expects. One test in it reads the configuration through `pan-python` and skips when that package is absent. Install it on a host with network access to run that check.

## Containerlab

```sh
docker build -t panos-emulator .
containerlab deploy -t containerlab.yml
```
