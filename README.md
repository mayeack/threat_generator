# ThreatGen

A FastAPI web application that generates realistic, Splunk-compliant JSON log files across 6 sourcetypes with embedded multi-phase APT threat activity. Nine threat campaigns simulate real-world attack patterns including nation-state APTs, ransomware, cryptojacking, credential phishing, and data exfiltration. Every sourcetype emits single-line JSON for consistent parsing and field extraction. Built for security analysts and threat hunters who need realistic data for detection engineering, SIEM tuning, and training exercises.

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
| **TernDoor** | 5 | sysmon, wineventlog, dns, firewall | DLL side-loading, persistence, driver install, C2 beacon | T1574.002, T1055, T1547.001, T1053.005, T1014, T1543.003, T1071.001 |
| **BruteEntry** | 3 | linux_secure, firewall, dns, http | SSH/Tomcat/Postgres brute-force from ORB IPs | T1110.001, T1110.003, T1595.002 |
| **PeerTime** | 4 | dns, http, linux_secure, firewall | ELF backdoor, BitTorrent P2P C2, Docker/BusyBox abuse | T1071.001, T1059.004, T1036.004, T1610 |
| **CobaltStrike** | 4 | sysmon, dns, firewall, wineventlog | PowerShell cradle, process hollowing, WinRM lateral movement, named pipe C2 | T1059.001, T1071.001, T1055.012, T1021.006, T1105 |
| **DarkGate** | 4 | sysmon, wineventlog, firewall | MSI loader, AutoIt execution, credential harvest, C2 exfiltration | T1566.001, T1218.007, T1059.010, T1555.003, T1041 |
| **CryptoJack** | 4 | linux_secure, http, firewall, dns | XMRig cryptominer, cron persistence, Stratum pool connections | T1496, T1059.004, T1053.003, T1105 |
| **RansomSim** | 4 | sysmon, wineventlog, firewall | Shadow copy deletion, service stop, file encryption, ransom note | T1486, T1490, T1489, T1059.001, T1547.001 |
| **PhishKit** | 4 | dns, http, firewall | AitM credential phishing proxy, OAuth token theft, mailbox access | T1566.002, T1557, T1539, T1114.002, T1078 |
| **SnakeByte** | 4 | sysmon, wineventlog, dns, firewall | SMB collection, 7-Zip staging, DNS tunnel exfil, HTTPS bulk transfer | T1048.001, T1071.004, T1132.001, T1560.001, T1005 |

TernDoor, BruteEntry, and PeerTime use IOC data (IPs, domains, hashes) sourced from the UAT-9244 Talos report. The remaining campaigns use realistic IOCs modeled after their respective malware families.

## Architecture

```
threatgen/
  __init__.py
  app.py                  # FastAPI app, lifespan, router mounts, static mount
  database.py             # SQLite schema (configs + runs), CRUD, seed from YAML
  models.py               # Pydantic models for API request/response
  websocket_manager.py    # Per-sourcetype WebSocket broadcast manager
  default_config.yaml     # Default topology, campaigns, sourcetype config

  engine/
    __init__.py
    config.py             # Dataclasses: EngineConfig, DiurnalConfig, etc.
    topology.py           # Network model: hosts, users, firewalls, IOCs
    scheduler.py          # Async event loop, diurnal curve, file writers

    generators/           # Normal traffic generators (one per sourcetype)
      base.py             #   BaseGenerator ABC
      wineventlog.py      #   Windows Security event log
      sysmon.py           #   Sysmon operational log
      linux_secure.py     #   Linux auth/syslog
      dns.py              #   Splunk Stream DNS
      http.py             #   Splunk Stream HTTP
      firewall.py         #   Cisco ASA firewall

    threats/              # Threat campaign generators
      base.py             #   BaseCampaign ABC
      orchestrator.py     #   Timer-based campaign orchestrator
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

  api/                    # FastAPI router modules
    __init__.py
    generator.py          #   Start/stop/pause/status
    config.py             #   Config get/update/list/save
    topology.py           #   Topology get/update
    campaigns.py          #   Campaign list/toggle/trigger
    stats.py              #   Runtime statistics
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
      campaigns.js        #   Campaign cards, toggles, IOCs, trigger

scripts/
  peak_hunt_queries.py    # Utility SPL query scripts

splunk/
  TA-threatgen/           # Splunk TA for log ingestion (props.conf, inputs.conf)
  TA-threat_hunting/      # Splunk TA for threat hunting (saved searches, KV store)

skills/
  peak-threat-hunting/    # PEAK framework threat hunting skill + templates
```

- **Backend**: FastAPI (async) with uvicorn, SQLite via aiosqlite
- **Frontend**: Vanilla HTML/CSS/JS served as static files (no build step)
- **Live streaming**: WebSocket per sourcetype at `/ws/logs/{sourcetype}`
- **Charts**: Chart.js loaded from CDN
- **Database**: SQLite with two tables -- `configs` (named configuration snapshots) and `runs` (generation run history with start/stop times and event counts)

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

This starts the server on `http://127.0.0.1:8899`. On first run, the SQLite database is created and seeded with the default configuration from `default_config.yaml`.

Log generation does **not** start automatically -- click **Start** in the web UI or call the API.

## Web UI

Open `http://127.0.0.1:8899` for the dark-themed SOC-style dashboard with five pages:

| Page | Purpose |
|---|---|
| **Dashboard** | Start/Stop/Pause controls, status card, EPS card, total event and threat event counters, uptime display, sourcetype bar chart, EPS line chart (last 60 samples) |
| **Log Viewer** | Six sourcetype tabs with live WebSocket streams, regex-based threat event highlighting (red), auto-scroll toggle, clear button, 500-line buffer per tab |
| **Configuration** | Edit EPS (slider), threat ratio, output directory, diurnal curve (enabled toggle, peak hours, peak/trough multiplier sliders), sourcetype weight table |
| **Topology** | Domain/DNS/NAT settings, network summary counts, editable tables for Windows hosts, Linux hosts, domain controllers, file servers, DMZ servers, firewalls, users (with add/delete) |
| **Campaigns** | Card grid for all 9 campaigns with enable/disable toggle, description, MITRE technique tags, interval range sliders, IOC display sections, manual Trigger Now button |

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
| `GET` | `/api/config` | Get active configuration |
| `PUT` | `/api/config` | Update active configuration (merge) |
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
| `GET` | `/api/llm/status` | Worker state, API key presence, per-sourcetype pool sizes, last error, active models |
| `POST` | `/api/llm/refresh` | Ask the variation worker to top up the scenario cache immediately |
| `GET` | `/api/llm/preview?sourcetype=dns&n=3` | Render up to N cached scenarios through the corresponding generator (no consumption) |

The `ANTHROPIC_API_KEY` is read from the environment **only**. It is never
stored in the database, the config file, or returned from any API. When
the key is missing, the LLM worker stays disabled and generators fall back
to deterministic pattern output — the dashboard shows an `LLM: fallback` pill.

### WebSocket

| Path | Description |
|---|---|
| `/ws/logs/{sourcetype}` | Live log stream for a sourcetype (`wineventlog`, `sysmon`, `linux_secure`, `dns`, `http`, `firewall`, or `all`) |

Messages arrive as `{sourcetype}|{log_line}`. The frontend reconnects automatically with a 3-second backoff.

## Configuration Options

All settings are editable through the web UI Configuration page or via the `/api/config` endpoint.

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
| **LLM** (`llm:`) | | See table below — controls the Claude-backed variation pool |

### LLM Settings (all optional, sensible defaults)

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

> **Security:** the API key is handled exclusively via the
> `ANTHROPIC_API_KEY` environment variable. It is never written to the
> database, log files, or the configuration file. All LLM responses are
> validated against strict JSON Schemas before being fed into the log
> formatters, and topology-derived IOCs (IPs, hostnames, users) are
> injected by the application rather than generated by the model.

## Output

Generated log files are written to the `output_dir` (default `./logs/`), created automatically when generation starts. Each sourcetype writes single-line JSON events to its own file. Log files are truncated each time the engine starts, so every run begins with clean data. Every JSON object contains a `timestamp` field used by Splunk for time extraction.

## Dependencies

| Package | Purpose |
|---|---|
| `fastapi` | Web framework and API |
| `uvicorn[standard]` | ASGI server with WebSocket support |
| `aiosqlite` | Async SQLite database access |
| `pyyaml` | YAML configuration parsing |
| `anthropic` | Claude SDK for LLM-backed log variations and campaign narratives (optional at runtime, required to install) |
| `jsonschema` | Validates LLM responses against strict per-sourcetype schemas |
