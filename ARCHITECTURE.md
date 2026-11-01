# Architecture

The emulator has one process and one source of truth: JSON state loaded at startup.

- `panos_emulator.py` handles HTTP, authentication, XML responses, state queries, candidate changes, commits, and jobs.
- `data/default.json` is the initial device state.
- `scenarios/*.json` are replaceable operating conditions.
- `Dockerfile` makes the endpoint portable.
- `containerlab.yml` places it in a repeatable lab topology.

Configuration is stored as a small Python structure and rendered into the PAN-OS tree on read. `action=show` renders the running configuration, `action=get` renders the candidate, and both walk an `xpath` under `/config`. Rendering on read keeps one representation in memory and one place to change when the supported subset grows.

The deliberate boundary is management-plane behavior, not packet forwarding. PAN-OS-specific workflows such as XML requests, XPath fields, commit jobs, HA state, logs, and device identity are worth emulating. App-ID classification and real firewall enforcement are outside this training device's scope.

User-ID state (mappings and tags) lives in the same JSON state, keyed by vsys, with expiry applied on read and write instead of by a timer thread. That keeps one lock and no background work, at the cost of an expired entry existing until the next request touches the table.
