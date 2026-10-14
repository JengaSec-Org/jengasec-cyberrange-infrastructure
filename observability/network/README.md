# Passive gateway observation

Owner: Observability for the sensors and event pipeline. The provisioning
owner retains firewall policy and participant access decisions.

`ansible/observability-gateway.yml` stages passive collection on the inventory's
`observability_gateway` hosts. Set `obs_network_interface` to the actual VPN
interface and explicitly enable `obs_network_approved`. Start with
`obs_network_start=false`; enable it after the IDS configuration check and
the event-agent TLS path succeed.

The role downloads signed distribution packages into an isolated package
cache and extracts them below the OBS tool directory. It does not install
packages, run package account hooks, change system package sources or start
a Docker daemon. GoFlow2 uses a versioned release and its runtime digest.
Suricata uses the compatible ET Open feed and a separate validation rule.

Three OBS systemd units collect the named interface:

| Unit | Function |
|---|---|
| `jengasec-softflowd` | Passive flow capture and loopback NetFlow export |
| `jengasec-goflow2` | Local decoding, in-memory sanitization and durable queue publication |
| `jengasec-suricata` | Passive IDS alerts and aggregate capture statistics |

The event agent forwards sanitized records over verified client TLS. GoFlow2
never writes its original output to a journal or file. Suricata disables
payload, packet, HTTP body and alert metadata output. Its EVE file contains
alerts and aggregate statistics; the reader rotates a fully consumed file at
32 MiB and retains one previous file. The agent's bounded queue and loss
counters remain the delivery authority.

Add all three units to the gateway's expected node-service list. A fresh
event-agent heartbeat alone does not prove that the capture processes are
running. Inspect IDS packet/drop counters and stats freshness as well as
flow observations. A running sensor with zero packets is a quiet sensor.
The decoder requests a new NetFlow v9 template from the local exporter after
each decoder restart. This preserves IPv4 and IPv6 decoding without waiting
for the exporter's normal template interval. The agent records decoder error
deltas and the last successful metrics scrape. Decoder errors also increase
the existing collection-error counter.

Capture covers the named VPN interface only. It does not imply visibility
into unrelated host interfaces or traffic between cluster workloads. Flow
records do not establish a firewall verdict. A passive IDS match is an
observation, not a score or a confirmed compromise.

## Firewall generator integration

`nft_verdict_logging.py` and `provision-worker-observation.patch` are a
reviewable integration for the provisioning generator. The helper inserts a
log-only companion before each unchanged terminal verdict rule. Each
companion uses the same selectors and limits its log rate to two records per
second with a burst of ten. It contains no participant or target identifier
in its fixed prefix. The terminal verdict has no rate limit.

Review the exact deployed source before installation. Keep its private copy
outside Git. `scripts/install-firewall-observation.py` compares that copy
with the target, rejects source drift, checks the expected generator shape
and writes an owner-only rollback copy. Its default is preflight; `--apply`
installs the hook and helper but does not restart the worker or invoke nft.

Before applying, render the patched generator with a read-only database
transaction and require native `nft -c` success. Compare the active rule
semantics before and after the approved worker restart. Exclude only the
new log-only rules and runtime rule handles from that comparison. Repeat
reconciliation and confirm the log companions remain. The rule verdict is
the observed decision at that rule; later network stages can still fail.

If validation fails, restore `provision_worker.py.original` from the private
rollback directory and restart the approved worker. Do not restore an old
ruleset over newer source-owner policy. To stop collection, stop the three
OBS sensor units and set the event agent's network collection flag to false.
Keep the event queue and evidence during rollback.
