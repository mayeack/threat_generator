#!/usr/bin/env python3
"""
PEAK Threat Hunt - Run all 13 SPL queries against index=threat_gen.
Uses Splunk REST API (urllib only). Set SPLUNK_HOST, SPLUNK_USER, SPLUNK_PASS (or SPLUNK_TOKEN).
"""
import os
import sys
import time
import json
import ssl
import urllib.request
import urllib.parse
import urllib.error

HOST = os.environ.get("SPLUNK_HOST", "https://127.0.0.1:8089")
USER = os.environ.get("SPLUNK_USER", "admin")
PASS = os.environ.get("SPLUNK_PASS", "")
TOKEN = os.environ.get("SPLUNK_TOKEN", "")
VERIFY = os.environ.get("SPLUNK_VERIFY", "false").lower() == "true"
EARLIEST = "-4h"
LATEST = "now"
ROW_LIMIT = 10000

QUERIES = [
    ("1. Data overview", 'index=threat_gen | stats count by sourcetype'),
    ("2. Sysmon suspicious processes (DLL sideloading, WSPrint, msiexec injection)",
     'index=threat_gen sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" | spath EventData.Image | search EventData.Image="*WSPrint*" OR EventData.Image="*msiexec*" OR EventData.Image="*busybox*" | table _time, Computer, EventID, EventData.Image, EventData.CommandLine, EventData.Hashes, EventData.RuleName'),
    ("3. Sysmon suspicious DLL loads",
     'index=threat_gen sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=7 | spath EventData.ImageLoaded | search EventData.ImageLoaded="*BugSplat*" OR EventData.Signed="false" | table _time, Computer, EventData.Image, EventData.ImageLoaded, EventData.Hashes, EventData.Signed'),
    ("4. Sysmon network connections to external IPs",
     'index=threat_gen sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=3 | spath EventData.DestinationPort | where EventData.DestinationPort="443" | table _time, Computer, EventData.Image, EventData.SourceIp, EventData.DestinationIp, EventData.DestinationPort, EventData.RuleName'),
    ("5. Sysmon registry and file events (persistence)",
     'index=threat_gen sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" | spath EventData.RuleName | search EventData.RuleName="*technique_id*" | table _time, Computer, EventID, EventData.RuleName, EventData.Image, EventData.TargetObject, EventData.TargetFilename, EventData.Details'),
    ("6. WinEventLog suspicious events (4688 process creation, 4698 scheduled tasks)",
     'index=threat_gen sourcetype="WinEventLog:Security" | search EventCode=4688 OR EventCode=4698 | search Message="*WSPrint*" OR Message="*schtasks*" OR Message="*msiexec*" | table _time, ComputerName, EventCode, TaskCategory, Message'),
    ("7. Linux brute-force (failed SSH)",
     'index=threat_gen sourcetype="linux_secure" | search message="*Failed password*" OR message="*Invalid user*" | stats count by hostname, message | sort -count | head 20'),
    ("8. Linux suspicious sudo/commands",
     'index=threat_gen sourcetype="linux_secure" | search message="*curl*" OR message="*docker*" OR message="*busybox*" OR message="*chmod*" OR message="*/tmp/*" | table _time, hostname, process, message'),
    ("9. Firewall denied connections (brute-force indicators)",
     'index=threat_gen sourcetype="cisco:asa" message_id="106023" | stats count by message | sort -count | head 20'),
    ("10. DNS queries for suspicious domains or IPs",
     'index=threat_gen sourcetype="stream:dns" | spath query{} | eval query=mvindex(\'query{}\', 0) | where like(query, "%.net") OR like(query, "%.xyz") OR like(query, "%.top") OR reply_code="NXDomain" | table _time, src_ip, query, reply_code, dest_ip'),
    ("11. HTTP suspicious paths (manager, loader, instrumentor)",
     'index=threat_gen sourcetype="stream:http" | search uri_path="/manager/html" OR uri_path="/loader" OR uri_path="/instrumentor" | table _time, src_ip, dest_ip, http_method, status, uri_path, site, http_user_agent'),
    ("12. HTTP 401 responses (brute-force)",
     'index=threat_gen sourcetype="stream:http" status=401 | stats count by src_ip, dest_ip, uri_path, site | sort -count'),
    ("13. Firewall outbound connections to unusual ports (BitTorrent C2)",
     'index=threat_gen sourcetype="cisco:asa" | search message="*6881*" OR message="*6882*" OR message="*6889*" OR message="*6969*" OR message="*51413*" | table _time, hostname, message_id, message'),
]


def make_request(url, data=None, method="GET"):
    ctx = ssl.create_default_context()
    if not VERIFY:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method=method)
    if TOKEN:
        req.add_header("Authorization", f"Bearer {TOKEN}")
    else:
        import base64
        cred = base64.b64encode(f"{USER}:{PASS}".encode()).decode()
        req.add_header("Authorization", f"Basic {cred}")
    if data:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        body = urllib.parse.urlencode(data).encode()
        req.data = body
    with urllib.request.urlopen(req, context=ctx, timeout=60) as r:
        return json.loads(r.read().decode())


def run_query(query):
    data = {
        "search": f"search {query}",
        "earliest_time": EARLIEST,
        "latest_time": LATEST,
        "max_count": ROW_LIMIT,
        "output_mode": "json",
    }
    try:
        resp = make_request(f"{HOST}/services/search/jobs", data=data, method="POST")
    except urllib.error.HTTPError as e:
        return None, f"Create job failed: {e.code} - {e.read().decode()[:500]}"
    except Exception as e:
        return None, str(e)
    sid = resp.get("sid")
    if not sid:
        return None, "No sid in response"
    for _ in range(120):
        try:
            j = make_request(f"{HOST}/services/search/jobs/{sid}?output_mode=json")
        except Exception as e:
            return None, str(e)
        entry = j.get("entry", [{}])[0]
        content = entry.get("content", {})
        if content.get("isDone"):
            break
        time.sleep(0.5)
    try:
        r = make_request(f"{HOST}/services/search/jobs/{sid}/results?output_mode=json&count={ROW_LIMIT}")
    except Exception as e:
        return None, str(e)
    return r, None


def main():
    if not PASS and not TOKEN:
        print("Set SPLUNK_PASS or SPLUNK_TOKEN (and optionally SPLUNK_HOST, SPLUNK_USER)")
        sys.exit(1)
    for label, query in QUERIES:
        print("\n" + "=" * 80)
        print(f"## {label}")
        print("=" * 80)
        print(f"Query: {query[:200]}{'...' if len(query) > 200 else ''}")
        print("-" * 40)
        data, err = run_query(query)
        if err:
            print(f"ERROR: {err}")
            continue
        results = data.get("results", [])
        if not results:
            print("(No results)")
            continue
        # Print as table
        keys = list(results[0].keys())
        for row in results:
            print(" | ".join(str(row.get(k, "")) for k in keys))
        print(f"\nTotal: {len(results)} rows")


if __name__ == "__main__":
    main()
