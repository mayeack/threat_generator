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
| `anthropic` | 0.96.0 | Claude SDK for LLM-backed log variation and campaign narratives |
| `jsonschema` | 4.25.0 | Validates LLM JSON responses before they reach generators |

## 1. Set Up

```bash
cd /Applications/ThreatGenerator
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### (Optional) Enable Claude-backed log variety

ThreatGen can call Anthropic Claude to populate a background pool of
scenario variations so that generated logs are not repetitive. This is
**optional**: if the API key is not set, the engine keeps running and
every sourcetype quietly falls back to the built-in pattern generators.

Set the key **via environment variable only**. The key is never persisted
to `threatgen.db`, `default_config.yaml`, or anywhere else on disk:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
python3 run.py
```

The Dashboard shows an **LLM** pill with three states:

| Pill | Meaning |
|---|---|
| `LLM: active (N/cap)` | Worker is online and the scenario cache is healthy. |
| `LLM: degraded (...)` | Last refresh failed (rate limit, timeout, invalid JSON). Existing cache is still served; generators fall back when a pool is empty. |
| `LLM: fallback` | No API key, worker disabled, or LLM explicitly off. 100% pattern-based output. |

Click **Regenerate LLM Pool** to force the worker to top up scenarios
immediately (subject to the configured concurrency / retry limits).

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

Go to the **Campaigns** tab and click **Trigger Now** on any of the 9 campaign cards. Watch correlated threat events appear across multiple sourcetypes in the Log Viewer.

## 7. Ingest into Splunk

ThreatGen writes six log files to `./logs/`, all in single-line JSON format for consistent Splunk ingestion:

| Log File | Format | Splunk Sourcetype |
|---|---|---|
| `wineventlog.log` | Single-line JSON | `WinEventLog:Security` |
| `sysmon.log` | Single-line JSON | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` |
| `linux_secure.log` | Single-line JSON | `linux_secure` |
| `stream_dns.log` | Single-line JSON | `stream:dns` |
| `stream_http.log` | Single-line JSON | `stream:http` |
| `cisco_asa.log` | Single-line JSON | `cisco:asa` |

All sourcetypes emit single-line JSON with a `timestamp` field. Log files are truncated each time the engine starts, so every run begins with clean data.

### Prerequisites

- A Splunk indexer (Enterprise or Cloud) with a receiving port enabled (default `9997`)
- A Splunk Universal Forwarder installed on the same machine as ThreatGen
- The `threat_gen` index created on the indexer (Settings > Indexes > New Index)

### Splunk TA Dependencies

Install the following Technology Add-ons on your **search head** (and indexer if it also serves as a search head). While ThreatGen's JSON output is self-describing, these TAs provide additional CIM mappings, lookups, and search-time field aliases needed to map fields like `src_ip`, `dest_ip`, `action`, and `user` for use with Splunk ES, security dashboards, and data model accelerations.

| TA | Splunkbase | Sourcetypes Covered |
|---|---|---|
| Splunk Add-on for Microsoft Windows | [Splunk_TA_windows](https://splunkbase.splunk.com/app/742) | `WinEventLog:Security` |
| Splunk Add-on for Microsoft Sysmon | [Splunk_TA_microsoft_sysmon](https://splunkbase.splunk.com/app/5709) | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` |
| Splunk Add-on for Unix and Linux | [Splunk_TA_nix](https://splunkbase.splunk.com/app/833) | `linux_secure` |
| Splunk Add-on for Cisco ASA | [Splunk_TA_cisco-asa](https://splunkbase.splunk.com/app/1620) | `cisco:asa` |
| Splunk Add-on for Stream Wire Data | [Splunk_TA_stream](https://splunkbase.splunk.com/app/1809) | `stream:dns`, `stream:http` |

> **Note:** The bundled `TA-threatgen` app uses `source::` stanzas with `KV_MODE = json` that take higher precedence than any TA-defined sourcetype stanzas. This ensures Splunk parses each line as JSON and extracts the `timestamp` field correctly. The TAs listed above are still needed for CIM mappings and field aliases.

### Step 1: Deploy TA-threatgen to the Splunk indexer

The bundled Splunk app at `splunk/TA-threatgen/` contains `source::`-based parsing rules that must be installed on the **indexer**. All sourcetypes emit single-line JSON. Without this app, Splunk may apply incorrect line-breaking or timestamp extraction rules from other installed TAs.

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

You should see all six sourcetypes with properly formatted JSON events and extracted fields.

### Reset stale data

If you previously indexed ThreatGen logs with incorrect parsing (merged JSON events, missing field extractions), clear the index before re-ingesting:

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
| Multiple JSON objects in one event | Indexer re-merges events with default `SHOULD_LINEMERGE = true` | Deploy `TA-threatgen` on the indexer |
| `WinEventLog:Security` events missing or sourcetype shows as `WinEventLog` | `Splunk_TA_windows` renames the sourcetype | `TA-threatgen` `source::` stanzas override this |
| Fields not extracted from JSON | Missing `KV_MODE = json` in `props.conf` | Deploy latest `TA-threatgen` on both indexer and forwarder |
| `linux_secure` or `cisco:asa` events missing entirely | No matching `inputs.conf` monitor on the forwarder | Verify `local/inputs.conf` paths and `disabled = false` |
| Timestamps show index time instead of event time | `TIME_PREFIX` not set to `"timestamp":"` in `props.conf` | Redeploy the latest `TA-threatgen` to both indexer and forwarder; follow "Reset stale data" steps above |
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
| `wineventlog` | `logs/wineventlog.log` | Single-line JSON | 1 |
| `sysmon` | `logs/sysmon.log` | Single-line JSON | 1 |
| `linux_secure` | `logs/linux_secure.log` | Single-line JSON | 1 |
| `dns` | `logs/stream_dns.log` | Single-line JSON | 1 |
| `http` | `logs/stream_http.log` | Single-line JSON | 1 |
| `cisco:asa` | `logs/cisco_asa.log` | Single-line JSON | 1 |

### Embedded Threat Campaigns

| Campaign | Class | Phases | Sourcetypes Affected |
|---|---|---|---|
| TernDoor | `TernDoorCampaign` | 5 | sysmon, wineventlog, dns, cisco:asa |
| BruteEntry | `BruteEntryCampaign` | 3 | linux_secure, cisco:asa, dns, http |
| PeerTime | `PeerTimeCampaign` | 4 | dns, http, linux_secure, cisco:asa |
| CobaltStrike | `CobaltStrikeCampaign` | 4 | sysmon, dns, cisco:asa, wineventlog |
| DarkGate | `DarkGateCampaign` | 4 | sysmon, wineventlog, cisco:asa |
| CryptoJack | `CryptoJackCampaign` | 4 | linux_secure, http, cisco:asa, dns |
| RansomSim | `RansomSimCampaign` | 4 | sysmon, wineventlog, cisco:asa |
| PhishKit | `PhishKitCampaign` | 4 | dns, http, cisco:asa |
| SnakeByte | `SnakeByteCampaign` | 4 | sysmon, wineventlog, dns, cisco:asa |

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
