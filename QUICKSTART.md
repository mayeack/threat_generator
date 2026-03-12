# ThreatGen Quick Start

Get ThreatGen running and generating logs in under 2 minutes.

## Prerequisites

- Python 3.9 or later
- A terminal

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

Point Splunk at the `./logs/` directory using a file monitor input. Suggested sourcetype mappings:

| File | Splunk Sourcetype |
|---|---|
| `wineventlog.log` | `WinEventLog` |
| `sysmon.log` | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` |
| `linux_secure.log` | `linux_secure` |
| `stream_dns.log` | `stream:dns` |
| `stream_http.log` | `stream:http` |
| `cisco_asa.log` | `cisco:asa` |

## What's Running

| Component | Location |
|---|---|
| Web UI | http://127.0.0.1:8899 |
| API docs (Swagger) | http://127.0.0.1:8899/docs |
| Generated logs | `./logs/` |
| Database | `threatgen.db` (project root) |

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
