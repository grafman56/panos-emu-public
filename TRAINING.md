# Training exercises

The emulator is management-plane only. It does not forward packets. Use it to practice the PAN-OS workflow and API client behavior.

## Candidate and commit

1. Query the running configuration with `type=config&action=show`.
2. Add a security rule with `type=config&action=set`.
3. Query the candidate with `type=config&action=get`. The rule is there, and the running configuration from step 1 is unchanged.
4. Run `type=config&action=validate`.
5. Commit with `type=commit`.
6. Poll the returned job with `type=op` and an XML jobs command. Status is nested under `job`, and the job is `FIN` with result `OK`.
7. Query the running configuration and confirm the rule is now present.

Both reads accept an `xpath`. Use `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules` to read only the rulebase, which is the path a client library sends.

## Troubleshooting

Switch scenarios and investigate the changed condition:

```sh
curl -X POST http://127.0.0.1:8080/scenario/ha-out-of-sync
curl -X POST http://127.0.0.1:8080/scenario/tunnel-down
curl -X POST http://127.0.0.1:8080/scenario/license-expiring
curl -X POST http://127.0.0.1:8080/scenario/high-sessions
```

Then return to `healthy`. A useful monitor should alert on the failure and clear the alert after the state returns to normal.

## Useful operational queries

```text
type=version
type=op with <show><system>...
type=op with <show><high-availability>...
type=op with <show><interface>...
type=op with <show><routing>...
type=op with <show><vpn>...
type=op with <show><session>...
type=op with <show><license>...
type=log
```

Each answer is keyed, so a script can read it: interfaces by name, routes under a virtual router, traps and VPN tunnels by tunnel name. The README lists every shape.

`show routing protocol bgp` is answered with an empty `<bgp/>`. No BGP is configured in this lab, and an empty branch is the truthful answer. An unknown command returns error 1 rather than a plausible-looking copy of another table.

## Containerlab lab access

After `containerlab deploy -t containerlab.yml`, the client node can reach the firewall over its own network path:

```sh
clab exec client -- curl http://panos/api?type=version
clab exec client -- curl 'http://panos/api?type=op&from=trust&to=untrust&application=ssl'
```

The image has a healthcheck, so the node is only ready once the API answers.
Host-side access (dashboard) stays on `http://127.0.0.1:8080/` via the published port.

## REST API

The emulator also serves a small JSON CRUD layer at `/restapi/v11.0/...`, mirroring the real PAN-OS split where XML is the full control plane and REST covers objects/policies/network resources:

```sh
curl http://127.0.0.1:8080/restapi/v11.0/Policies/SecurityRules
curl http://127.0.0.1:8080/restapi/v11.0/Network/Zones
```

Like the real firewall, REST changes still commit through the XML API (`type=commit`). Supported resources in this lab: `Policies/SecurityRules`, `Network/Zones`, `Objects/Addresses`, `Objects/Services`.

## User-ID: IP-to-user mappings and tags

The emulator keeps an in-memory table of IP-to-user mappings and IP tags. It is the firewall side of a NAC-to-firewall integration. It does not enforce anything.

The `<uid-message>` shapes (login, logout, register, unregister, register-user, unregister-user, clear) follow Palo Alto's published page [Apply User-ID Mapping and Populate Dynamic Groups (API)](https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-use-cases/apply-user-id-mapping-and-populate-dynamic-address-groups-api). The two `show` commands below are **not** on that page and come from the author's memory of the CLI.

```sh
# 1. Get a key (works before you have one, even when PANOS_API_KEY is set)
curl 'http://127.0.0.1:8080/api?type=keygen&user=admin&password=x'

# 2. Log a user in on an IP (timeout in minutes, default 45, 0 = never) and tag the IP (timeout in seconds, 0 = never)
curl -X POST http://127.0.0.1:8080/api --data-urlencode type=user-id --data-urlencode \
  'cmd=<uid-message><version>2.0</version><type>update</type><payload>
        <login><entry name="corp\jsmith" ip="10.10.10.11" timeout="20"/></login>
        <register><entry ip="10.10.10.11"><tag><member timeout="3600">staff</member></tag></entry></register>
      </payload></uid-message>'

# 3. Read both tables
curl -G http://127.0.0.1:8080/api --data-urlencode type=op --data-urlencode \
  'cmd=<show><user><ip-user-mapping><all/></ip-user-mapping></user></show>'
curl -G http://127.0.0.1:8080/api --data-urlencode type=op --data-urlencode \
  'cmd=<show><object><registered-ip><all/></registered-ip></object></show>'
```

`<logout>` removes a mapping. `<unregister>` removes the named tags, or the whole IP when it names none. Entries expire on their timeout. A session that ends without a logout leaves its mapping until the timeout, as on a real firewall. Switching scenario clears both tables.

### Policy that matches on user or tag

A security rule can carry `source-user` and `source-tag` (lists use `<member>`, as on PAN-OS). `security-policy-match` then asks User-ID who is at the `source` address:

```sh
# allow ssh from any address tagged role:staff
curl -G http://127.0.0.1:8080/api --data-urlencode type=config --data-urlencode action=set \
  --data-urlencode "xpath=security/rules/entry[@name='staff-ssh']" --data-urlencode \
  'element=<entry name="staff-ssh"><source>any</source><destination>any</destination><application>ssh</application><source-tag><member>role:staff</member></source-tag><action>allow</action></entry>'
curl -G http://127.0.0.1:8080/api --data-urlencode type=op --data-urlencode \
  'cmd=<test><security-policy-match><from>trust</from><to>dc</to><source>10.10.10.11</source><application>ssh</application></security-policy-match></test>'
```

`source-tag` matches a tag on the address or a tag on the user mapped to it (`<register-user>`). The lab treats a tag as a stand-in for a dynamic address group. A user tag needs an existing user mapping.

Not modeled: real dynamic address group objects, group mapping, and the application-default, service and URL columns of a rule.

## Check these on a real firewall

A pass here means your code works. It does not mean the firewall will accept it. Re-check these on a real PAN-OS (a PA-VM in eval is enough):

1. **The two `show` commands.** `show user ip-user-mapping` and `show object registered-ip` output shape and element names.
2. **Login timeout and tag timeout.** The units (minutes and seconds here), the defaults, and that a `0` means "never".
3. **Tag-to-rule matching.** Real PAN-OS matches rules on address objects and dynamic address groups, not on a bare tag. Create the group, put the tag in its match criteria, and commit.
4. **Error codes and text.** Which malformed `<uid-message>` is rejected, and with what code.
5. **Commit and locks.** A real commit queues, validates deeper, and can fail on locks or dependencies.
6. **Rate and size limits.** The docs advise at most 5 concurrent User-ID API calls and batching of bursts.
7. **Tag timeout limit.** The Palo page gives 30 days for IP tags and prints a different number for user tags. This lab uses 2,592,000 s for both.
8. **Which vsys.** The API takes `vsys` as a query parameter and defaults to `vsys1`. On a real firewall the parameter only applies where Panorama manages the device; a standalone firewall answers from its own vsys, and the mapping table you read there is the one the dataplane uses. Set `PANOS_VSYS=vsys1,vsys2` to give the lab two tenants, and check that a login or a user tag in one does not answer a policy match in the other. The lab keeps user tags per vsys; confirm that on your firewall.
9. **Mirror mode output.** `show routing protocol bgp peer` element names (`peer-address`, `remote-as`, `status`, `status-duration`, `msg-total-in`, `prefixes-received`), the peer name `peer-<address>`, the `A B`, `A O` and `A C` route flags, and the extra `ip`, `zone` and `virtual-router` fields on `show interface`. Mirror mode takes the values from FRR and renames them. It does not copy a real firewall's output byte for byte.
