---
description: Splunk MCP queries for ThreatGen must always target the Splunk Cloud stack at https://aisoc-shw-ac1b0ac6a138.stg.splunkcloud.com/ — never a local Splunk instance. Applies to every session that uses the user-splunk-mcp-server tools.
alwaysApply: true
---

# Splunk MCP Target (ThreatGen)

ThreatGen forwards events via HEC to the Splunk Cloud stack
`https://aisoc-shw-ac1b0ac6a138.stg.splunkcloud.com/` (`index=threat_gen`). All
validation, troubleshooting, and skill workflows — PEAK hunting, Exposure
Analytics setup, TA development, ML detection, dashboard building — must run
against that stack, **not** a developer's local Splunk on
`MYEACK-M-P9QJ` or any other host.

## The invariant

Before the first `splunk_run_query` / `splunk_get_*` call in any session, verify
the MCP target with `splunk_get_info`. The response **must** show:

- `serverName` in the `aisoc-shw-ac1b0ac6a138` family (search head or indexer
  instance name from that stack — never `MYEACK-M-P9QJ`)
- `server_roles` containing `search_head` (or a Splunk Cloud managed role),
  not a single-node local `indexer` with `license_master` on the same host

If the probe returns a local hostname (e.g. `MYEACK-M-P9QJ`), **stop** and do
not proceed. Local-Splunk results will mislead every downstream conclusion —
index contents, lexicon, tstats counts, Exposure Analytics validation, ES
correlation searches, and KV store lookups are all specific to the cluster and
will not match Splunk Cloud.

## If the MCP is pointing at the wrong instance

1. Tell the user which host the MCP currently resolves to and ask them to
   reconfigure the `user-splunk-mcp-server` MCP in Cursor to target
   `https://aisoc-shw-ac1b0ac6a138.stg.splunkcloud.com/` (port 8089 for the
   management API; the MCP descriptor handles auth).
2. Do **not** try to work around it by filtering on `splunk_server=...` —
   a local Splunk will not have the ES apps, Exposure Analytics KV stores,
   or the TA-threat_gen indexer-tier configs that the skills depend on.
3. Only resume tool calls once `splunk_get_info` reports the Splunk Cloud
   serverName.

## Why this rule exists

A previous session spent ~20 minutes diagnosing an Exposure Analytics
"nt_host not found" issue using an MCP that was silently pointed at the
user's laptop. Every `tstats` and `walklex` result described the local dev
Splunk (which lacked the TA and the EA data model), not the Splunk Cloud
instance where EA Validate actually runs. The fix was switching the MCP
target, not the code. This rule makes sure we check first, always.

## Reference

- Stack URL: `https://aisoc-shw-ac1b0ac6a138.stg.splunkcloud.com/`
- Index: `threat_gen`
- HEC endpoint: `https://http-inputs-aisoc-shw-ac1b0ac6a138.stg.splunkcloud.com:443/services/collector/event`
- Related skills (all assume this target): `skills/exposure-analytics-setup/`,
  `skills/peak-threat-hunting/`, and any future `splunk-*` skill.
