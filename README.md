# ThreatGen

A FastAPI web application that generates realistic, Splunk-compliant log files across 6 sourcetypes with embedded **UAT-9244** APT threat activity. Built for security analysts and threat hunters who need realistic data for detection engineering, SIEM tuning, and training exercises.

## What It Does

ThreatGen produces a continuous stream of normal enterprise network traffic interlaced with multi-phase APT campaign activity across correlated sourcetypes. All output is formatted for direct ingestion into Splunk.

### Sourcetypes

| Sourcetype | Output File | Format |
|---|---|---|
| WinEventLog | `wineventlog.log` | Windows Event Log XML |
| Sysmon | `sysmon.log` | Sysmon XML |
| linux_secure | `linux_secure.log` | Syslog (PAM/sshd) |
| Splunk Stream DNS | `stream_dns.log` | JSON |
| Splunk Stream HTTP | `stream_http.log` | JSON |
| Cisco ASA Firewall | `cisco_asa.log` | Cisco ASA syslog |

### Threat Campaigns

Three UAT-9244 campaigns cycle through phases on each trigger, producing correlated events across multiple sourcetypes simultaneously:

| Campaign | Phases | Sourcetypes Affected | Techniques |
|---|---|---|---|
| **TernDoor** | 5 | sysmon, wineventlog, dns, firewall | DLL sideloading, persistence, driver install, C2 beacon |
| **BruteEntry** | 3 | linux_secure, firewall, dns, http | SSH/Tomcat/Postgres brute-force from ORB IPs |
| **PeerTime** | 4 | dns, http, linux_secure, firewall | ELF backdoor, BitTorrent C2, Docker/BusyBox abuse |

IOC data (IPs, domains, hashes) is sourced from the UAT-9244 Talos report for accurate Splunk threat intel correlation.

## Architecture

```
threatgen/
  app.py                  # FastAPI app, lifespan, router mounts, static mount
  database.py             # SQLite schema, CRUD, seed from default_config.yaml
  models.py               # Pydantic models for API request/response
  websocket_manager.py    # Per-sourcetype WebSocket broadcast manager
  default_config.yaml     # Default topology, campaigns, sourcetype config

  engine/                 # Core generation engine (no FastAPI dependencies)
    config.py             # Dataclasses for parsed config
    topology.py           # Network model: hosts, users, firewalls, IOCs
    scheduler.py          # Async event loop, diurnal curve, file writers
    generators/           # One module per sourcetype (normal traffic)
    threats/              # UAT-9244 campaign generators + orchestrator
    formatters/           # Output format helpers (WinEventLog, Sysmon XML, syslog, JSON)

  api/                    # FastAPI router modules
  static/                 # Frontend SPA (index.html, css/, js/)
```

- **Backend**: FastAPI (async) with uvicorn, SQLite via aiosqlite
- **Frontend**: Vanilla HTML/CSS/JS served as static files (no build step)
- **Live streaming**: WebSocket per sourcetype at `/ws/logs/{sourcetype}`
- **Charts**: Chart.js loaded from CDN

## Installation

**Requirements**: Python 3.9+

```bash
cd /Applications/ThreatGen
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
| **Dashboard** | Start/Stop/Pause controls, EPS gauge, total/threat event counters, sourcetype bar chart, EPS line chart |
| **Log Viewer** | Tabs per sourcetype, live WebSocket log stream, threat event highlighting, auto-scroll, clear |
| **Configuration** | Edit EPS, threat ratio, output directory, diurnal curve settings, sourcetype weights |
| **Topology** | Manage domain, DNS, NAT, hosts (Windows/Linux/DC/file/DMZ), firewalls, users |
| **Campaigns** | Per-campaign cards with enable/disable toggle, MITRE technique tags, IOC display, manual trigger |

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
| `GET` | `/api/configs` | List all saved configurations |
| `POST` | `/api/configs` | Save current config with a name |

### Topology

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/topology` | Get topology from active config |
| `PUT` | `/api/topology` | Update topology |

### Campaigns

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/campaigns` | List campaigns with metadata |
| `PUT` | `/api/campaigns/{id}` | Toggle campaign enabled/disabled |
| `POST` | `/api/campaigns/{id}/trigger` | Manually trigger a campaign |

### Stats

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/stats` | State, uptime, total events, events by sourcetype, threat events, current EPS |

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

## Output

Generated log files are written to the `output_dir` (default `./logs/`), created automatically when generation starts. Each sourcetype writes to its own file in append mode.

## Dependencies

| Package | Purpose |
|---|---|
| `fastapi` | Web framework and API |
| `uvicorn[standard]` | ASGI server with WebSocket support |
| `aiosqlite` | Async SQLite database access |
| `pyyaml` | YAML configuration parsing |
