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
| `linux_secure.log` | BSD syslog | `linux_secure` |
| `stream_dns.log` | Single-line JSON (Splunk Stream) | `stream:dns` |
| `stream_http.log` | Single-line JSON (Splunk Stream) | `stream:http` |
| `cisco_asa.log` | Syslog with PRI header + `%ASA-` message ID | `cisco:asa` |

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

> **Note:** These TAs include `props.conf` settings (`rename` directives, line breaking rules) that conflict with ThreatGen's log format when applied at index time. If any of these TAs are also installed on the **indexer**, you must deploy the indexer-side parsing app in Step 2 below to override them.

### Step 1: Create the forwarder app

```bash
sudo mkdir -p /opt/splunkforwarder/etc/apps/threatgen_inputs/local
sudo mkdir -p /opt/splunkforwarder/etc/apps/threatgen_inputs/default
```

Create `/opt/splunkforwarder/etc/apps/threatgen_inputs/default/app.conf`:

```ini
[install]
state = enabled

[ui]
is_visible = false
label = ThreatGen Inputs

[launcher]
version = 1.0.0
description = Monitors ThreatGen APT log files for forwarding to Splunk
```

Create `/opt/splunkforwarder/etc/apps/threatgen_inputs/local/inputs.conf`:

> **Important:** Update the monitor paths below if ThreatGen is installed somewhere other than `/Applications/ThreatGen`.

```ini
[monitor:///Applications/ThreatGen/logs/wineventlog.log]
disabled = false
index = threat_gen
sourcetype = WinEventLog:Security
source = threatgen:wineventlog

[monitor:///Applications/ThreatGen/logs/sysmon.log]
disabled = false
index = threat_gen
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
source = threatgen:sysmon

[monitor:///Applications/ThreatGen/logs/linux_secure.log]
disabled = false
index = threat_gen
sourcetype = linux_secure
source = threatgen:linux_secure

[monitor:///Applications/ThreatGen/logs/stream_dns.log]
disabled = false
index = threat_gen
sourcetype = stream:dns
source = threatgen:stream_dns

[monitor:///Applications/ThreatGen/logs/stream_http.log]
disabled = false
index = threat_gen
sourcetype = stream:http
source = threatgen:stream_http

[monitor:///Applications/ThreatGen/logs/cisco_asa.log]
disabled = false
index = threat_gen
sourcetype = cisco:asa
source = threatgen:cisco_asa
```

Create `/opt/splunkforwarder/etc/apps/threatgen_inputs/local/props.conf`:

```ini
[stream:dns]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N
TIME_PREFIX = "timestamp":"
MAX_TIMESTAMP_LOOKAHEAD = 32
KV_MODE = json

[stream:http]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N
TIME_PREFIX = "timestamp":"
MAX_TIMESTAMP_LOOKAHEAD = 32
KV_MODE = json

[WinEventLog:Security]
LINE_BREAKER = ([\r\n]+)(?=\d{2}/\d{2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+[AP]M)
SHOULD_LINEMERGE = false
TIME_FORMAT = %m/%d/%Y %I:%M:%S %p
MAX_TIMESTAMP_LOOKAHEAD = 24

[XmlWinEventLog:Microsoft-Windows-Sysmon/Operational]
LINE_BREAKER = ([\r\n]+)(?=<Event\s)
SHOULD_LINEMERGE = false
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N
TIME_PREFIX = SystemTime="
MAX_TIMESTAMP_LOOKAHEAD = 32

[cisco:asa]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_FORMAT = %b %d %H:%M:%S
MAX_TIMESTAMP_LOOKAHEAD = 15
TIME_PREFIX = >\w{3}\s+

[linux_secure]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_FORMAT = %b %d %H:%M:%S
MAX_TIMESTAMP_LOOKAHEAD = 15
```

### Step 2: Create the indexer-side parsing app

If your Splunk indexer has TAs installed that define these sourcetypes (Splunk_TA_windows, Splunk_TA_cisco-asa, Splunk_TA_microsoft_sysmon, Splunk_TA_nix), their `rename` directives and parsing rules will conflict with ThreatGen's log format. Deploy this app on the **indexer** to override them using source-based stanza precedence.

> **Skip this step** if your indexer has none of these TAs installed.

```bash
sudo mkdir -p /opt/splunk/etc/apps/threatgen_inputs/local
sudo mkdir -p /opt/splunk/etc/apps/threatgen_inputs/default
```

Create `/opt/splunk/etc/apps/threatgen_inputs/default/app.conf`:

```ini
[install]
state = enabled

[ui]
is_visible = false
label = ThreatGen Inputs

[launcher]
version = 1.0.0
description = Parsing configuration for ThreatGen APT log data
```

Create `/opt/splunk/etc/apps/threatgen_inputs/local/props.conf`:

```ini
[source::threatgen:wineventlog]
sourcetype = WinEventLog:Security
SHOULD_LINEMERGE = true
BREAK_ONLY_BEFORE = ^\d{2}/\d{2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+[AP]M
TIME_FORMAT = %m/%d/%Y %I:%M:%S %p
MAX_TIMESTAMP_LOOKAHEAD = 24
rename = WinEventLog:Security

[source::threatgen:sysmon]
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
SHOULD_LINEMERGE = true
BREAK_ONLY_BEFORE = <Event\s+xmlns=
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N
TIME_PREFIX = SystemTime="
MAX_TIMESTAMP_LOOKAHEAD = 32
rename = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

[source::threatgen:linux_secure]
sourcetype = linux_secure
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_FORMAT = %b %d %H:%M:%S
MAX_TIMESTAMP_LOOKAHEAD = 15

[source::threatgen:stream_dns]
sourcetype = stream:dns
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N
TIME_PREFIX = "timestamp":"
MAX_TIMESTAMP_LOOKAHEAD = 32
KV_MODE = json

[source::threatgen:stream_http]
sourcetype = stream:http
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N
TIME_PREFIX = "timestamp":"
MAX_TIMESTAMP_LOOKAHEAD = 32
KV_MODE = json

[source::threatgen:cisco_asa]
sourcetype = cisco:asa
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_FORMAT = %b %d %H:%M:%S
MAX_TIMESTAMP_LOOKAHEAD = 15
```

The `source::` stanzas match the custom `source` values set in the forwarder's `inputs.conf` and take **higher precedence** than sourcetype-based stanzas from the TAs. The `rename` directives on the multi-line sourcetypes explicitly preserve the intended sourcetype name, preventing TAs like Splunk_TA_windows from renaming `WinEventLog:Security` to `WinEventLog`.

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
# Restart the indexer (only if you deployed the indexer-side app)
sudo /opt/splunk/bin/splunk restart

# Restart the forwarder
sudo /opt/splunkforwarder/bin/splunk restart
```

Verify data is flowing in Splunk:

```
index=threat_gen | stats count by sourcetype
```

You should see all six sourcetypes with properly formatted events.

### Troubleshooting: TA conflicts

If you have Splunk TAs installed and did not deploy the indexer-side app, you may see these symptoms:

| Symptom | Cause |
|---|---|
| `WinEventLog:Security` events missing or sourcetype shows as `WinEventLog` | `Splunk_TA_windows` has `rename = WinEventLog` in its `props.conf` |
| Sysmon events show sourcetype `XmlWinEventLog` or `xmlwineventlog` | `Splunk_TA_windows` and `Splunk_TA_microsoft_sysmon` both rename this sourcetype |
| `stream:dns` or `stream:http` events show multiple JSON objects merged into one event | Missing `SHOULD_LINEMERGE = false` at the indexer parsing stage |
| `cisco:asa` or `linux_secure` events missing | TA parsing rules conflict with ThreatGen's format |

The fix in all cases is to deploy the indexer-side `props.conf` from Step 2.

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
| `linux_secure` | `logs/linux_secure.log` | BSD syslog | 1 |
| `dns` | `logs/stream_dns.log` | JSON | 1 |
| `http` | `logs/stream_http.log` | JSON | 1 |
| `firewall` | `logs/cisco_asa.log` | Syslog with PRI + `%ASA-` | 1 |

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
