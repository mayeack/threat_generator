---
description: Splunk MCP queries for ThreatGen must always target the Splunk Cloud stack that ThreatGen currently forwards to — never a local Splunk instance. Resolve the target from ThreatGen's live HEC config; never hardcode a stack hostname. Applies to every session that uses the user-splunk-mcp-server tools.
alwaysApply: true
---

# Splunk MCP Target (ThreatGen)

ThreatGen forwards events via HEC to a Splunk Cloud stack (`index=threat_gen`).
All validation, troubleshooting, and skill workflows — PEAK hunting, Exposure
Analytics setup, TA development, ML detection, dashboard building — must run
against **that** stack, not a developer's local Splunk.

The stack changes regularly. **Never hardcode a stack hostname — in this rule,
in a skill, or in a query.** Resolve it at runtime instead.

## Resolving the current target

ThreatGen's own HEC config is the source of truth. With the server running:

```bash
curl -s http://127.0.0.1:8899/api/hec/config | python3 -c \
  "import json,sys; print(json.load(sys.stdin)['url'])"
# -> https://http-inputs-<stack>.<env>.splunkcloud.com:443
```

That returns the **ingest** host. Splunk Cloud serves HEC on a separate
`http-inputs-` hostname from the search head; strip that prefix to get the
search head / MCP target:

| Role | Host |
|---|---|
| HEC ingest (ThreatGen writes here) | `http-inputs-<stack>.<env>.splunkcloud.com:443` |
| Search head / management (MCP reads here) | `<stack>.<env>.splunkcloud.com` (mgmt API on 8089) |

If HEC is not yet configured, ask the user for the stack URL rather than
guessing or reusing a hostname from a previous session — stale stacks go
NXDOMAIN and every downstream conclusion silently breaks.

## The invariant

Before the first `splunk_run_query` / `splunk_get_*` call in any session, verify
the MCP target with `splunk_get_info`. The response **must**:

- Report a `serverName` belonging to the same stack as the configured HEC URL
  (the `<stack>` token above) — a Splunk Cloud search head or indexer instance.
- Contain `search_head` (or a Splunk Cloud managed role) in `server_roles` —
  **not** a single-node local `indexer` with `license_master` on the same host.

The negative check is the durable one: a local single-node Splunk with
`indexer` + `license_master` + `kv_store` on one host is never the right
target, whatever the current stack happens to be.

If the probe returns a local hostname, **stop** and do not proceed.
Local-Splunk results will mislead every downstream conclusion — index contents,
lexicon, tstats counts, Exposure Analytics validation, ES correlation searches,
and KV store lookups are all specific to the cluster and will not match Splunk
Cloud.

## If the MCP is pointing at the wrong instance

1. Tell the user which host the MCP currently resolves to, and which host the
   HEC config says it should be. Ask them to reconfigure the
   `user-splunk-mcp-server` MCP in Cursor to target the search head derived
   above (port 8089 for the management API; the MCP descriptor handles auth).
2. Do **not** try to work around it by filtering on `splunk_server=...` —
   a local Splunk will not have the ES apps, Exposure Analytics KV stores,
   or the TA-threat_gen indexer-tier configs that the skills depend on.
3. Only resume tool calls once `splunk_get_info` reports the correct stack.

## Why this rule exists

A previous session spent ~20 minutes diagnosing an Exposure Analytics
"nt_host not found" issue using an MCP that was silently pointed at the
user's laptop. Every `tstats` and `walklex` result described the local dev
Splunk (which lacked the TA and the EA data model), not the Splunk Cloud
instance where EA Validate actually runs. The fix was switching the MCP
target, not the code. This rule makes sure we check first, always.

A later session found this rule itself pinned to a decommissioned stack that
had gone NXDOMAIN — the rule was steering every session at a host that no
longer existed. Hence: resolve, don't hardcode.

## Reference

- Current stack: resolve from `/api/hec/config` (see above). Not recorded here.
- Index: `threat_gen`
- Setting up a new endpoint + HEC token: see **Adding a HEC destination** in
  [`README.md`](../../README.md).
- Related skills (all assume the resolved target): `skills/exposure-analytics-setup/`,
  `skills/peak-threat-hunting/`, and any future `splunk-*` skill.
