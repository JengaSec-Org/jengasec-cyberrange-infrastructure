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

Suricata also has a hard per-file limit of 64 MiB, configured through
`obs_network_suricata_file_size_limit_bytes`; it must exceed the reader's
32 MiB rotation threshold. This bounds the current and previous EVE files to
128 MiB with the default settings, even when the reader cannot keep up.
The kernel enforces the cap. A small launcher observes only Suricata's open
EVE inode, survives the reader's HUP rotation, and stops its child at the cap
with exit status 75. Automatic restart is disabled for that status. Cap
handling does not generate a core dump, including on hosts with a piped core
handler. Existing source bytes remain available to the event agent; the final
JSON line may be incomplete. Capture is unavailable from that point until an
operator resumes it. The expected service alert identifies the stopped
sensor, and IDS statistics become stale. Queue overflow can still evict
records with explicit loss counters during a prolonged delivery outage.

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

## Recovering from the IDS file cap

Confirm `jengasec-suricata.service` failed with the file-cap exit status 75,
check free space, and resolve the reader or delivery backlog before resuming
capture. Leave the event agent running so it can deliver complete records.
It can rotate a fully consumed EVE file normally; an incomplete trailing JSON
line remains unread and requires the following explicit recovery.

1. Verify the event queue has drained and `ids_offset` in the event-agent
   state reaches the end of the last complete line. Pause only the event-agent
   timer and wait for its current service invocation to finish before moving
   source files.
2. Preserve the capped EVE file, any existing previous file, and the reader
   state in a private evidence directory. Do not truncate unread source data
   or clear the event queue. If `eve.json` still exists, move it to
   `eve.json.1` after preserving the previous file. A partial final record
   cannot be reconstructed; the reader reports the unconsumed tail as input
   rotation loss when it sees the new file.
3. Run `systemctl reset-failed jengasec-suricata.service`, then
   `systemctl start jengasec-suricata.service`. Run
   `systemctl start jengasec-event-agent.service` once before restarting its
   timer, so the timer has a fresh service completion after a long pause.
   Confirm the process file-size limit, fresh IDS statistics, successful
   delivery, and recovery of the expected-service alert.

Private recovery exports need their own evidence retention; they are outside
the two-file source-spool bound. Raising the cap postpones another stop but
does not repair sustained reader lag.

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
