# ThreatGen

A FastAPI web application that generates realistic, Splunk-compliant JSON log files across 6 sourcetypes with embedded multi-phase APT threat activity. Nine threat campaigns simulate real-world attack patterns including nation-state APTs, ransomware, cryptojacking, credential phishing, and data exfiltration. Every sourcetype emits single-line JSON for consistent parsing and field extraction. Built for security analysts and threat hunters who need realistic data for detection engineering, SIEM tuning, and training exercises.

Logs can be written to disk for Universal Forwarder ingestion and/or streamed directly to a Splunk HTTP Event Collector (HEC). An optional Claude-backed variation engine adds scenario diversity and multi-step campaign narratives without ever persisting its API key.

## What It Does

ThreatGen produces a continuous stream of normal enterprise network traffic interlaced with multi-phase threat campaign activity across correlated sourcetypes. All output is single-line JSON with a `timestamp` field, formatted for direct ingestion into Splunk with `KV_MODE = json`.

### Sourcetypes

| Sourcetype | Output File | Format |
|---|---|---|
| WinEventLog | `wineventlog.log` | Single-line JSON |
| Sysmon | `sysmon.log` | Single-line JSON |
| linux_secure | `linux_secure.log` | Single-line JSON |
| Splunk Stream DNS | `stream_dns.log` | Single-line JSON |
| Splunk Stream HTTP | `stream_http.log` | Single-line JSON |
| Cisco ASA Firewall | `cisco_asa.log` | Single-line JSON |

### Threat Campaigns

Nine campaigns cycle through phases on each trigger, producing correlated events across multiple sourcetypes simultaneously:

| Campaign | Phases | Sourcetypes Affected | Techniques | MITRE IDs |
|---|---|---|---|---|
| **TernDoor** | 5 | sysmon, wineventlog, stream:dns, cisco:asa | DLL side-loading, persistence, driver install, C2 beacon | T1574.002, T1055, T1547.001, T1053.005, T1014, T1543.003, T1071.001 |
| **BruteEntry** | 3 | linux_secure, cisco:asa, stream:dns, stream:http | SSH/Tomcat/Postgres brute-force from ORB IPs | T1110.001, T1110.003, T1595.002 |
| **PeerTime** | 4 | stream:dns, stream:http, linux_secure, cisco:asa | ELF backdoor, BitTorrent P2P C2, Docker/BusyBox abuse | T1071.001, T1059.004, T1036.004, T1610 |
| **CobaltStrike** | 4 | sysmon, stream:dns, cisco:asa, wineventlog | PowerShell cradle, process hollowing, WinRM lateral movement, named pipe C2 | T1059.001, T1071.001, T1055.012, T1021.006, T1105 |
| **DarkGate** | 4 | sysmon, wineventlog, cisco:asa | MSI loader, AutoIt execution, credential harvest, C2 exfiltration | T1566.001, T1218.007, T1059.010, T1555.003, T1041 |
| **CryptoJack** | 4 | linux_secure, stream:http, cisco:asa, stream:dns | XMRig cryptominer, cron persistence, Stratum pool connections | T1496, T1059.004, T1053.003, T1105 |
| **RansomSim** | 4 | sysmon, wineventlog, cisco:asa | Shadow copy deletion, service stop, file encryption, ransom note | T1486, T1490, T1489, T1059.001, T1547.001 |
| **PhishKit** | 4 | stream:dns, stream:http, cisco:asa | AitM credential phishing proxy, OAuth token theft, mailbox access | T1566.002, T1557, T1539, T1114.002, T1078 |
| **SnakeByte** | 4 | sysmon, wineventlog, stream:dns, cisco:asa | SMB collection, 7-Zip staging, DNS tunnel exfil, HTTPS bulk transfer | T1048.001, T1071.004, T1132.001, T1560.001, T1005 |

TernDoor, BruteEntry, and PeerTime use IOC data (IPs, domains, hashes) sourced from the UAT-9244 Talos report. The remaining campaigns use realistic IOCs modeled after their respective malware families.

### Entity-discovery fields (Splunk ES 8 Exposure Analytics)

Every generated JSON event carries the four CIM-aligned Exposure Analytics key fields at the **top level** (not nested in `EventData` or the syslog `message`), so Splunk ES 8 Exposure Analytics can auto-populate its Asset, IP, User, and MAC inventories from a streaming source with no pipe operators in the event search:

| Field | Inventory it feeds | Source in ThreatGen |
|---|---|---|
| `nt_host` | Asset | `host.hostname` for the host the event originates on |
| `ip` | IP | Primary observed IP (`src_ip` when available, else `dest_ip`) |
| `user_id` | User | `user.username` (also mirrored as `user` for CIM) |
| `mac` | MAC | Deterministic locally-administered MAC derived from hostname at topology load (`02:xx:xx:xx:xx:xx`) |

Supporting fields `src_ip`, `dest_ip`, and `dest_nt_host` are also promoted to the top level so network-event correlation and IP↔Asset reconciliation work without custom extractions.

#### Full-topology Asset coverage invariant

Every host defined in the active topology must be the top-level `nt_host` on at least one generator path. A host that only appears as `dest_nt_host` or embedded in a message cannot be discovered as an Asset by Exposure Analytics. The generators are wired for this as follows:

| Topology bucket | Sourcetype | Generator path | Notes |
|---|---|---|---|
| `windows_hosts` | `WinEventLog:Security` | `WinEventLogGenerator._host_for_event` (default) | Covers EventCode 4624/4625/4634/4672/4688/4738 |
| `domain_controllers` | `WinEventLog:Security` | `WinEventLogGenerator._host_for_event` for **4768/4769** | Kerberos AS-REQ / TGS-REQ events originate on DCs |
| `file_servers` | `WinEventLog:Security` | `WinEventLogGenerator._host_for_event` for **5140/5145** | SMB share access / detailed share access originate on file servers |
| `linux_hosts` | `linux_secure` | `LinuxSecureGenerator._render` (~70%) | sshd / sudo events |
| `dmz_servers` | `linux_secure` | `LinuxSecureGenerator._render` (~30%) | 30% of sshd/sudo events are sourced from a random `dmz_server` |
| `firewalls` | `cisco:asa` | `CiscoAsaGenerator` | `src_ip` + `dest_ip` populate the IP inventory |

Editing the topology? Add the corresponding `Topology.random_<role>()` helper **and** wire it into at least one generator as `nt_host` before shipping; otherwise the new host will be invisible to Exposure Analytics. The [`exposure-analytics-setup` skill](skills/exposure-analytics-setup/SKILL.md) documents the validating MCP query (distinct counts should match the topology: 32 hosts, 32 MACs, 13 users for the default config).

To wire this up inside Splunk ES 8 end-to-end (predefined + custom streaming sources, compliance windows, preflight / post-setup validation), invoke the [`exposure-analytics-setup` skill](skills/exposure-analytics-setup/SKILL.md).

## Architecture

```
threatgen/
  __init__.py
  app.py                  # FastAPI app, lifespan, router mounts, static mount
  database.py             # SQLite schema (configs + runs), CRUD, seed from YAML
  models.py               # Pydantic models for API request/response + LLM/HEC DTOs
  websocket_manager.py    # Per-sourcetype WebSocket broadcast manager
  default_config.yaml     # Default topology, campaigns, sourcetype + LLM + HEC config

  engine/
    __init__.py
    config.py             # Dataclasses: EngineConfig, DiurnalConfig, LLMConfig, HECConfig
    topology.py           # Network model: hosts, users, firewalls, IOCs
    scheduler.py          # Async event loop, diurnal curve, file writers, HEC fan-out

    generators/           # Normal traffic generators (one per sourcetype)
      base.py             #   BaseGenerator ABC (supports render_from_scenario)
      wineventlog.py      #   Windows Security event log
      sysmon.py           #   Sysmon operational log
      linux_secure.py     #   Linux auth/syslog
      dns.py              #   Splunk Stream DNS
      http.py             #   Splunk Stream HTTP
      firewall.py         #   Cisco ASA firewall

    threats/              # Threat campaign generators
      base.py             #   BaseCampaign ABC
      orchestrator.py     #   Timer-based campaign orchestrator
      llm_plan.py         #   Claude-backed multi-step campaign planner
      terndoor.py         #   TernDoor APT backdoor
      bruteentry.py       #   BruteEntry brute-force scanner
      peertime.py         #   PeerTime P2P backdoor
      cobaltstrike.py     #   CobaltStrike beacon
      darkgate.py         #   DarkGate MaaS loader
      cryptojack.py       #   CryptoJack XMRig miner
      ransomsim.py        #   RansomSim ransomware
      phishkit.py         #   PhishKit AitM phishing
      snakebyte.py        #   SnakeByte data exfiltration

    formatters/           # Output formatters (all produce single-line JSON)
      base.py             #   BaseFormatter ABC
      json_fmt.py         #   Generic JSON (DNS, HTTP)
      syslog_fmt.py       #   SyslogFormatter (linux_secure), CiscoASAFormatter
      sysmon_fmt.py       #   Sysmon operational XML-style JSON
      wineventlog_fmt.py  #   Windows Security event JSON

    llm/                  # Optional Anthropic Claude variation engine
      runtime.py          #   Lifecycle: configure/start/stop/refresh
      worker.py           #   Background cache top-up loop
      cache.py            #   Per-sourcetype bounded scenario pools
      client.py           #   Async Anthropic SDK wrapper, retries, timeouts
      planner.py          #   Multi-step campaign narrative planner
      prompts.py          #   Per-sourcetype and campaign prompt templates
      schemas.py          #   JSON Schemas for validating LLM output
      key_store.py        #   OS keychain / env-var resolver for ANTHROPIC_API_KEY
      exceptions.py       #   Typed errors surfaced to the /api/llm/status view

    hec/                  # Splunk HTTP Event Collector forwarder
      runtime.py          #   Lifecycle: configure/start/stop/restart, stats
      forwarder.py        #   Async bounded queue, batching, retry, drop-oldest
      client.py           #   httpx-based HEC client (event/raw endpoints)
      key_store.py        #   OS keychain / env-var resolver for SPLUNK_HEC_TOKEN

  api/                    # FastAPI router modules
    __init__.py
    generator.py          #   Start/stop/pause/status
    config.py             #   Config get/update/list/save
    topology.py           #   Topology get/update
    campaigns.py          #   Campaign list/toggle/trigger + hunt metadata
    stats.py              #   Runtime statistics
    llm.py                #   LLM status/config/key/pause/resume/refresh/preview
    hec.py                #   HEC config/key/test/stats
    websocket.py          #   WebSocket log streaming

  static/                 # Frontend SPA (no build step)
    index.html            #   App shell, sidebar nav, Chart.js CDN
    css/style.css         #   Dark SOC theme, responsive layout
    js/
      app.js              #   Router, status polling, fetch helper
      dashboard.js        #   Controls, stats cards, bar + line charts
      log-viewer.js       #   Per-sourcetype WebSocket tabs, threat highlighting
      config-editor.js    #   EPS, diurnal, sourcetype weight editing
      topology-editor.js  #   Host/firewall/user table editing
      campaigns.js        #   Campaign cards, toggles, IOCs, trigger, hunt button
      hunt-guides.js      #   Per-campaign easy/medium/hard hunt guidance + SPL
      hunt-modal.js       #   Threat-hunt modal renderer (opened from Campaigns)
      settings.js         #   Generative AI + Splunk HEC settings, keychain mgmt

scripts/
  peak_hunt_queries.py    # Utility SPL query scripts
  package_ta.sh           # Builds dist/TA-threat_gen-<version>.tgz for Splunk Cloud upload
  validate_ta.sh          # Runs splunk-appinspect with --included-tags cloud on the tarball

splunk/
  TA-threat_gen/          # Splunk TA for log ingestion (props, transforms, fields, inputs)
                          #   Build the uploadable package with ./scripts/package_ta.sh;
                          #   result lands in dist/TA-threat_gen-<version>.tgz.
  TA-threat_hunting/      # Splunk TA for threat hunting (saved searches, KV store)

skills/
  peak-threat-hunting/       # PEAK framework threat hunting skill + templates
  exposure-analytics-setup/  # Wire ThreatGen into Splunk ES 8 Exposure Analytics
                             #   entity discovery (Assets/IP/User/MAC inventories)
```

- **Backend**: FastAPI (async) with uvicorn, SQLite via aiosqlite
- **Frontend**: Vanilla HTML/CSS/JS served as static files (no build step)
- **Live streaming**: WebSocket per sourcetype at `/ws/logs/{sourcetype}`
- **Charts**: Chart.js loaded from CDN
- **Database**: SQLite with two tables -- `configs` (named configuration snapshots) and `runs` (generation run history with start/stop times and event counts)
- **Outputs**: File writers (one per sourcetype, truncated on each start) and an optional Splunk HEC forwarder with its own bounded queue
- **Secret handling**: The Anthropic API key and Splunk HEC token are resolved from environment variables first, then the OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service). They are never written to the SQLite config, YAML, logs, or any API response.

## Installation

**Requirements**: Python 3.9+

```bash
cd /Applications/ThreatGenerator
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Running

```bash
python3 run.py
```

This starts the server on `http://127.0.0.1:8899` (loopback only). On first run, the SQLite database is created and seeded with the default configuration from `default_config.yaml`.

Log generation does **not** start automatically -- click **Start** in the web UI or call the API.

## Web UI

Open `http://127.0.0.1:8899` for the dark-themed SOC-style dashboard with six pages:

| Page | Purpose |
|---|---|
| **Dashboard** | Start/Stop/Pause controls, status card, EPS card, total event and threat event counters, uptime display, sourcetype bar chart, EPS line chart (last 60 samples), LLM and HEC status pills |
| **Log Viewer** | Six sourcetype tabs with live WebSocket streams, regex-based threat event highlighting (red), auto-scroll toggle, clear button, 500-line buffer per tab |
| **Configuration** | Edit EPS (slider), threat ratio, output directory, diurnal curve (enabled toggle, peak hours, peak/trough multiplier sliders), sourcetype weight table |
| **Topology** | Domain/DNS/NAT settings, network summary counts, editable tables for Windows hosts, Linux hosts, domain controllers, file servers, DMZ servers, firewalls, users (with add/delete) |
| **Campaigns** | Card grid for all 9 campaigns with enable/disable toggle, description, MITRE technique tags, interval range sliders, IOC display sections, manual Trigger Now button, and a **Hunt** button that opens tiered (easy/medium/hard) PEAK-style hunt guidance with copy-ready SPL |
| **Settings** | Unified page for Generative AI (Claude) and Splunk HEC: API key / HEC token management via the OS keychain, model selection, pool tuning, HEC URL / TLS verification / index / source / sourcetype map / batch and queue tuning, Test Connection and Regenerate Pool actions |

## API Reference

Interactive docs are available at `http://127.0.0.1:8899/docs` when the server is running.

### Generator Control

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/generator/start` | Start log generation |
| `POST` | `/api/generator/stop` | Stop log generation |
| `POST` | `/api/generator/pause` | Pause or resume generation |
| `GET` | `/api/generator/status` | Current state, run ID, uptime, total events |

### Configuration

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/config` | Get active configuration (secrets are never returned) |
| `PUT` | `/api/config` | Update active configuration (deep merge) |
| `GET` | `/api/configs` | List all saved configuration snapshots (metadata only) |
| `POST` | `/api/configs` | Save current active config as a named snapshot |

> **Note:** Saved configuration snapshots can be listed and created but there is currently no API endpoint to activate (load) a previously saved snapshot.

### Topology

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/topology` | Get topology from active config |
| `PUT` | `/api/topology` | Update topology |

### Campaigns

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/campaigns` | List all 9 campaigns with metadata, MITRE techniques, and IOCs |
| `PUT` | `/api/campaigns/{id}` | Toggle campaign enabled/disabled |
| `POST` | `/api/campaigns/{id}/trigger` | Manually trigger a campaign (returns `events_generated` count) |

### Stats

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/stats` | State, uptime, total events, events by sourcetype, threat events, current EPS |

### LLM (Claude-backed variation engine)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/llm/status` | Worker state, key presence/source, per-sourcetype pool sizes, last error, active models |
| `GET` | `/api/llm/config` | Safe-to-expose LLM config (key is never returned) |
| `PUT` | `/api/llm/config` | Update LLM config fields (enabled, models, pool tuning, timeouts) |
| `GET` | `/api/llm/key` | Reports whether a key is configured and where it came from (`env` / `keychain` / `none`) |
| `PUT` | `/api/llm/key` | Store the Anthropic API key in the OS keychain (validated, never logged/echoed) |
| `DELETE` | `/api/llm/key` | Remove the Anthropic API key from the OS keychain |
| `POST` | `/api/llm/pause` | Stop the variation worker in-process (cleared on restart) |
| `POST` | `/api/llm/resume` | Resume the variation worker when eligible |
| `POST` | `/api/llm/refresh` | Ask the variation worker to top up the scenario cache immediately |
| `GET` | `/api/llm/preview?sourcetype=stream:dns&n=3` | Render up to N cached scenarios through the corresponding generator (no consumption) |

Key resolution order is **env var → OS keychain → disabled**. The `ANTHROPIC_API_KEY` environment variable always takes precedence. Keys are validated for format, never written to the database or YAML, and never returned from any endpoint. When no key is available, the LLM worker stays disabled and generators fall back to deterministic pattern output — the dashboard shows an `LLM: fallback` pill.

### Splunk HEC (HTTP Event Collector forwarder)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/hec/config` | Safe-to-expose HEC config (token is never returned) |
| `PUT` | `/api/hec/config` | Update HEC config (enabled, URL, TLS verify, index/source/host, sourcetype map, batching) |
| `POST` | `/api/hec/test` | Send a synthetic event to verify connectivity; returns status code, latency, and error (if any) |
| `GET` | `/api/hec/key` | Reports whether a HEC token is configured and where it came from |
| `PUT` | `/api/hec/key` | Store the HEC token in the OS keychain (validated UUID shape, never logged/echoed) |
| `DELETE` | `/api/hec/key` | Remove the HEC token from the OS keychain |
| `GET` | `/api/hec/stats` | Forwarder stats: running flag, events sent/failed/dropped, batch counts, queue depth, last success/error |

Token resolution order is **env var (`SPLUNK_HEC_TOKEN`) → OS keychain → disabled**. When HEC is enabled but the token is missing the forwarder starts in a degraded state and records errors via `/api/hec/stats`. The forwarder uses a bounded in-memory queue with drop-oldest overflow to prevent memory exhaustion.

### WebSocket

| Path | Description |
|---|---|
| `/ws/logs/{sourcetype}` | Live log stream for a sourcetype (`wineventlog`, `sysmon`, `linux_secure`, `stream:dns`, `stream:http`, `cisco:asa`, or `all`) |

Messages arrive as `{sourcetype}|{log_line}`. The frontend reconnects automatically with a 3-second backoff.

## Configuration Options

All settings are editable through the web UI (Configuration and Settings pages) or via the matching API endpoints.

### Engine (`/api/config`)

| Setting | Default | Description |
|---|---|---|
| `output_dir` | `./logs` | Directory for generated log files |
| `eps` | `5` | Events per second (baseline) |
| `threat_ratio` | `0.08` | Proportion of events that are threat activity |
| **Diurnal curve** | | |
| `enabled` | `true` | Simulate day/night traffic variation |
| `peak_hours` | `[8, 18]` | Start and end of peak hours |
| `peak_multiplier` | `1.5` | EPS multiplier during peak |
| `trough_multiplier` | `0.3` | EPS multiplier during off-peak |
| **Sourcetype weights** | | Per-sourcetype relative generation weight |
| **Campaign settings** | | Per-campaign: `enabled`, `interval_minutes`, IOC lists |

### LLM (`/api/llm/config`)

| Setting | Default | Description |
|---|---|---|
| `enabled` | `true` | Master switch. Set `false` to force pattern-only output even when the key is set. |
| `model` | `claude-haiku-4-5` | Model used for per-sourcetype scenario batches (cost-efficient). |
| `campaign_model` | `claude-sonnet-4-5` | Model used for multi-step threat campaign narratives. |
| `variation_pool_size` | `50` | Max scenarios cached per sourcetype. |
| `low_water` | `10` | Refill is triggered when a pool falls below this count. |
| `batch_size` | `10` | Scenarios requested per LLM call. |
| `refresh_interval_minutes` | `60` | Background refresh cadence (also triggers early on low-water). |
| `request_timeout_s` | `30` | Per-request timeout to the Anthropic API. |
| `max_concurrent_requests` | `2` | Concurrency cap for in-flight LLM requests. |
| `max_retries` | `2` | Retries on transient errors; then marks the cache degraded. |
| `max_tokens_variations` | `4096` | Output token cap for scenario batches. |
| `max_tokens_campaign` | `4096` | Output token cap for campaign plans. |

### Splunk HEC (`/api/hec/config`)

| Setting | Default | Description |
|---|---|---|
| `enabled` | `false` | Master switch for the forwarder. |
| `url` | _example_ | Full HEC URL (including scheme and port). |
| `verify_tls` | `true` | Verify the HEC endpoint TLS certificate. Disable only for self-signed lab setups. |
| `default_index` | `main` | Fallback index applied to events without an explicit index. |
| `default_source` | `threatgen` | Fallback `source` field. |
| `default_host` | `threatgen` | Fallback `host` field. |
| `sourcetype_map` | OOTB defaults | Mapping from internal sourcetype keys (`wineventlog`, `sysmon`, `linux_secure`, `stream:dns`, `stream:http`, `cisco:asa`) to Splunk sourcetypes on the wire. Ships pre-populated with the out-of-the-box Splunk names (e.g., `sysmon` -> `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, `wineventlog` -> `WinEventLog:Security`) so HEC-only deployments match every bundled hunt guide, dashboard, and skill without TA re-sourcetyping. Edit or clear entries in Settings to override. |
| `batch_size` | `100` | Events per HEC batch. |
| `flush_interval_s` | `2.0` | Max time to hold events before flushing a partial batch. |
| `queue_max` | `10000` | Bounded queue capacity. Overflow drops the oldest events. |
| `request_timeout_s` | `10.0` | Per-request timeout. |
| `max_retries` | `3` | Retries on transient HTTP errors. |

> **Security:** both the Anthropic API key (`ANTHROPIC_API_KEY`) and the Splunk HEC token (`SPLUNK_HEC_TOKEN`) are handled **exclusively** via environment variables and/or the OS keychain. They are never written to the database, config file, log files, or any API response. LLM responses are validated against strict JSON Schemas before being fed into the log formatters, and topology-derived IOCs (IPs, hostnames, users) are injected by the application rather than generated by the model.

## Output

Generated log files are written to the `output_dir` (default `./logs/`), created automatically when generation starts. Each sourcetype writes single-line JSON events to its own file. Log files are truncated each time the engine starts, so every run begins with clean data. Every JSON object contains a `timestamp` field used by Splunk for time extraction.

When the Splunk HEC forwarder is enabled, every emitted event is fanned out to both the on-disk file and the HEC queue. The forwarder batches events, honors the configured index/source/host/sourcetype map, and retries on transient errors. Use `/api/hec/stats` or the Settings page to watch queue depth and success/failure counters.

## Dependencies

| Package | Purpose |
|---|---|
| `fastapi` | Web framework and API |
| `uvicorn[standard]` | ASGI server with WebSocket support |
| `aiosqlite` | Async SQLite database access |
| `pyyaml` | YAML configuration parsing |
| `anthropic` | Claude SDK for LLM-backed log variations and campaign narratives (optional at runtime, required to install) |
| `jsonschema` | Validates LLM responses against strict per-sourcetype schemas |
| `httpx` | Async HTTP client used by the Splunk HEC forwarder |
| `keyring` | OS keychain integration for storing the Anthropic API key and HEC token at rest (never written to the app database or YAML) |
