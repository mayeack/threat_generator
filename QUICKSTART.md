# ThreatGen Quick Start

Get ThreatGen running and generating logs in under 2 minutes.

## Prerequisites

- Python 3.9 or later
- A terminal

### Python Dependencies

Defined in `requirements.txt`:

| Package | Min Version | Purpose |
|---|---|---|
| `fastapi` | 0.115.0 | Async web framework, REST API, static file serving |
| `uvicorn[standard]` | 0.34.0 | ASGI server with WebSocket support |
| `aiosqlite` | 0.20.0 | Async SQLite driver for configuration persistence |
| `pyyaml` | 6.0 | YAML parsing for `default_config.yaml` |

## 1. Set Up

```bash
cd /Applications/ThreatGen
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 2. Start the Server

```bash
python3 run.py
```

The server starts on **http://127.0.0.1:8899**. On first launch, it creates a SQLite database and loads the default configuration automatically.

## 3. Open the Dashboard

Navigate to **http://127.0.0.1:8899** in your browser. You'll see the dark SOC-themed dashboard.

## 4. Start Generating Logs

Click the **Start** button on the Dashboard page. You should immediately see:

- The EPS gauge and event counters updating
- The sourcetype bar chart filling in
- Log files appearing in the `./logs/` directory

## 5. View Live Logs

Switch to the **Log Viewer** tab. Select a sourcetype to watch events stream in real time via WebSocket. Threat events are highlighted in red.

## 6. Trigger a Threat Campaign

Go to the **Campaigns** tab and click **Trigger Now** on any campaign card (TernDoor, BruteEntry, or PeerTime). Watch correlated threat events appear across multiple sourcetypes in the Log Viewer.

## 7. Ingest into Splunk

ThreatGen writes six log files to `./logs/`, each in a Splunk-native format:

| Log File | Format | Splunk Sourcetype |
|---|---|---|
| `wineventlog.log` | Multi-line key=value (Windows Security Auditing) | `WinEventLog:Security` |
| `sysmon.log` | Multi-line XML (Sysmon events) | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` |
| `linux_secure.log` | Syslog with ISO 8601 timestamps | `linux_secure` |
| `stream_dns.log` | Single-line JSON (Splunk Stream) | `stream:dns` |
| `stream_http.log` | Single-line JSON (Splunk Stream) | `stream:http` |
| `cisco_asa.log` | Syslog with PRI header + ISO 8601 timestamps | `cisco:asa` |

Log files are truncated each time the engine starts, so every run begins with clean data.

### Prerequisites

- A Splunk indexer (Enterprise or Cloud) with a receiving port enabled (default `9997`)
- A Splunk Universal Forwarder installed on the same machine as ThreatGen
- The `threat_gen` index created on the indexer (Settings > Indexes > New Index)

### Splunk TA Dependencies

Install the following Technology Add-ons on your **search head** (and indexer if it also serves as a search head). These TAs provide the field extractions, CIM mappings, and lookups needed to parse ThreatGen's log formats into meaningful fields (`src_ip`, `dest_ip`, `action`, `user`, etc.) for use with Splunk ES, security dashboards, and data model accelerations.

| TA | Splunkbase | Sourcetypes Covered |
|---|---|---|
| Splunk Add-on for Microsoft Windows | [Splunk_TA_windows](https://splunkbase.splunk.com/app/742) | `WinEventLog:Security` |
| Splunk Add-on for Microsoft Sysmon | [Splunk_TA_microsoft_sysmon](https://splunkbase.splunk.com/app/5709) | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` |
| Splunk Add-on for Unix and Linux | [Splunk_TA_nix](https://splunkbase.splunk.com/app/833) | `linux_secure` |
| Splunk Add-on for Cisco ASA | [Splunk_TA_cisco-asa](https://splunkbase.splunk.com/app/1620) | `cisco:asa` |
| Splunk Add-on for Stream Wire Data | [Splunk_TA_stream](https://splunkbase.splunk.com/app/1809) | `stream:dns`, `stream:http` |

> **Note:** The bundled `TA-threatgen` app uses `source::` stanzas that take higher precedence than any TA-defined sourcetype stanzas. This prevents TAs from renaming sourcetypes or applying conflicting line-breaking rules. The TAs are still needed for search-time field extractions and CIM mappings.

### Step 1: Deploy TA-threatgen to the Splunk indexer

The bundled Splunk app at `splunk/TA-threatgen/` contains `source::`-based parsing rules that must be installed on the **indexer**. Without this app, Splunk's default `SHOULD_LINEMERGE = true` re-merges events at index time, causing multi-line events to be mangled and single-line JSON events to be concatenated.

```bash
sudo cp -r splunk/TA-threatgen /opt/splunk/etc/apps/TA-threatgen
```

### Step 2: Deploy TA-threatgen to the forwarder

Install the same app on the Universal Forwarder and create a `local/inputs.conf` to enable the file monitors.

```bash
sudo cp -r splunk/TA-threatgen /opt/splunkforwarder/etc/apps/TA-threatgen
sudo mkdir -p /opt/splunkforwarder/etc/apps/TA-threatgen/local
```

Create `/opt/splunkforwarder/etc/apps/TA-threatgen/local/inputs.conf`:

> **Important:** Update the monitor paths below if ThreatGen is installed somewhere other than `/Applications/ThreatGenerator`.

```ini
[monitor:///Applications/ThreatGenerator/logs/wineventlog.log]
disabled = false
index = threat_gen
sourcetype = WinEventLog:Security
source = threatgen:wineventlog

[monitor:///Applications/ThreatGenerator/logs/sysmon.log]
disabled = false
index = threat_gen
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
source = threatgen:sysmon

[monitor:///Applications/ThreatGenerator/logs/linux_secure.log]
disabled = false
index = threat_gen
sourcetype = linux_secure
source = threatgen:linux_secure

[monitor:///Applications/ThreatGenerator/logs/stream_dns.log]
disabled = false
index = threat_gen
sourcetype = stream:dns
source = threatgen:stream_dns

[monitor:///Applications/ThreatGenerator/logs/stream_http.log]
disabled = false
index = threat_gen
sourcetype = stream:http
source = threatgen:stream_http

[monitor:///Applications/ThreatGenerator/logs/cisco_asa.log]
disabled = false
index = threat_gen
sourcetype = cisco:asa
source = threatgen:cisco_asa
```

### Step 3: Configure the forwarder output

If the forwarder doesn't already have an `outputs.conf`, create `/opt/splunkforwarder/etc/system/local/outputs.conf`:

```ini
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
disabled = false
server = <your_indexer_ip>:9997
```

Replace `<your_indexer_ip>` with your Splunk indexer's IP address or hostname.

### Step 4: Restart and verify

```bash
# Restart the indexer
sudo /opt/splunk/bin/splunk restart

# Restart the forwarder
sudo /opt/splunkforwarder/bin/splunk restart
```

Verify data is flowing in Splunk:

```
index=threat_gen | stats count by sourcetype
```

You should see all six sourcetypes with properly formatted events.

### Reset stale data

If you previously indexed ThreatGen logs with incorrect event breaking (merged JSON events, mangled multi-line events), clear the index before re-ingesting:

```bash
sudo /opt/splunk/bin/splunk stop
sudo /opt/splunk/bin/splunk clean eventdata -index threat_gen
sudo /opt/splunk/bin/splunk start
```

Then restart ThreatGen (which truncates the log files) and the forwarder:

```bash
# Restart ThreatGen to generate fresh logs
curl -X POST http://127.0.0.1:8899/api/generator/stop
curl -X POST http://127.0.0.1:8899/api/generator/start

# Restart the forwarder to re-read from the beginning of each file
sudo /opt/splunkforwarder/bin/splunk restart
```

### Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Multiple JSON objects in one event (stream:dns/http) | Indexer re-merges events with default `SHOULD_LINEMERGE = true` | Deploy `TA-threatgen` on the indexer |
| `WinEventLog:Security` events missing or sourcetype shows as `WinEventLog` | `Splunk_TA_windows` renames the sourcetype | `TA-threatgen` `source::` stanzas override this |
| Sysmon XML events fragmented or merged | Missing `LINE_BREAKER` for `<Event` boundaries | Deploy `TA-threatgen` on both indexer and forwarder |
| `linux_secure` or `cisco:asa` events missing entirely | No matching `inputs.conf` monitor on the forwarder | Verify `local/inputs.conf` paths and `disabled = false` |
| Timestamps show index time instead of event time (`cisco:asa`, `WinEventLog:Security`, etc.) | Stale `TA-threatgen` with outdated `TIME_PREFIX` or `TIME_FORMAT` in `props.conf` | Redeploy the latest `TA-threatgen` to both indexer and forwarder; follow "Reset stale data" steps above |
| Old malformed events still appearing after fix | Stale data in the `threat_gen` index | Follow "Reset stale data" steps above |

## What's Running

| Component | Location |
|---|---|
| Web UI | http://127.0.0.1:8899 |
| API docs (Swagger) | http://127.0.0.1:8899/docs |
| Generated logs | `./logs/` (configurable via `output_dir` in config) |
| Database | `threatgen.db` (project root, auto-created) |
| Default config | `threatgen/default_config.yaml` |

### Log Output Files

| Internal Name | File | Format | Lines per Event |
|---|---|---|---|
| `wineventlog` | `logs/wineventlog.log` | Multi-line key=value | ~15-25 |
| `sysmon` | `logs/sysmon.log` | Multi-line XML (`<Event>...</Event>`) | ~20-30 |
| `linux_secure` | `logs/linux_secure.log` | Syslog (ISO 8601) | 1 |
| `dns` | `logs/stream_dns.log` | JSON | 1 |
| `http` | `logs/stream_http.log` | JSON | 1 |
| `firewall` | `logs/cisco_asa.log` | Syslog with PRI + ISO 8601 | 1 |

### Embedded Threat Campaigns (UAT-9244)

| Campaign | Class | Phases | Sourcetypes Affected |
|---|---|---|---|
| TernDoor | `TernDoorCampaign` | 5 | sysmon, wineventlog, dns, firewall |
| BruteEntry | `BruteEntryCampaign` | 3 | linux_secure, firewall, dns, http |
| PeerTime | `PeerTimeCampaign` | 4 | dns, http, linux_secure, firewall |

## Common Tasks

### Change the EPS

Go to **Configuration** and adjust the EPS slider, or call:

```bash
curl -X PUT http://127.0.0.1:8899/api/config \
  -H "Content-Type: application/json" \
  -d '{"eps": 20}'
```

### Enable/Disable a Campaign

Toggle campaigns from the **Campaigns** tab, or via API:

```bash
curl -X PUT http://127.0.0.1:8899/api/campaigns/terndoor \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'
```

### Stop Generation

Click **Stop** on the Dashboard, or call:

```bash
curl -X POST http://127.0.0.1:8899/api/generator/stop
```

## Next Steps

- See [README.md](README.md) for full API reference, configuration options, and architecture details
- Explore the topology editor to customize the simulated network
- Adjust the diurnal curve to simulate realistic day/night traffic patterns
- Use the threat ratio setting to control the density of APT activity
