from __future__ import annotations

import json
from typing import Any

_COMMON_RULES = """\
You are generating diverse, realistic security-log scenario *data*, not final
log lines. Your output will be merged with live topology values (hostnames,
IPs, users, timestamps) by downstream code. Therefore:

- Return STRICT JSON only. No prose, no markdown, no comments.
- NEVER invent our internal hostnames, IP addresses, SIDs, or user names -
  downstream code will fill those in from a trusted topology.
- Use placeholders like "<HOST>", "<USER>", "<SRC_IP>" only if the schema
  explicitly allows them. Otherwise omit topology-specific fields.
- Every scenario object MUST match the schema you are given. Unknown or
  extra fields will be ignored but must still be JSON-serializable.
- Vary intent: mix benign-admin, developer, user, and subtly-suspicious-
  but-not-attack activity. Do NOT produce confirmed threats in these
  baseline scenarios; threat campaigns are handled separately.
- Keep each scenario's narrative field under ~300 chars; it is for humans
  reading demo logs, not for machines.
"""


_WINEVENTLOG_PROMPT = """\
Generate a batch of Windows Security Event Log scenarios for a mid-sized
corporate Windows environment. Each scenario describes ONE event.

Return JSON of the form:
{"scenarios": [ {...}, {...} ]}

Each scenario must include at minimum:
  - event_code: one of 4624, 4625, 4634, 4672, 4688, 4738, 4768, 4769, 5140, 5145
  - narrative:  short plain-English reason for the event

For 4624 (successful logon) include logon_type (2/3/5/7/10), logon_process,
auth_package, and optionally external_source=true when logon_type=10.
For 4625 (failed logon) include failure_reason and optionally external_source.
For 4688 (process creation) include process_path, parent_process_path,
command_line (may be identical to process_path), and token_elevation.
For 4672 (special logon) include privileges (2-5 item list from:
SeSecurityPrivilege, SeBackupPrivilege, SeRestorePrivilege,
SeTakeOwnershipPrivilege, SeDebugPrivilege, SeSystemEnvironmentPrivilege,
SeLoadDriverPrivilege, SeImpersonatePrivilege).
For 4738 (account changed) set use_admin_user=true so the subject is an admin.
For 4768 (Kerberos TGT requested) and 4769 (Kerberos service ticket
requested) the event is logged by a domain controller; narrative should
describe the authenticating user and requested service.
For 5140 (network share accessed) and 5145 (detailed file share access)
the event is logged by a file server; narrative should describe the
share being accessed.

Distribute a batch roughly as: 35% 4624, 5% 4625, 18% 4634, 8% 4672,
15% 4688, 2% 4738, 6% 4768, 7% 4769, 2% 5140, 2% 5145. Vary process
paths (real Windows tooling, Office apps, browsers, developer tools,
PowerShell, wscript, conhost, etc.).
"""


_SYSMON_PROMPT = """\
Generate Sysmon event scenarios for a Windows workstation/server fleet.
Return JSON {"scenarios": [...]}.

event_id choices: 1 (ProcessCreate), 3 (NetworkConnect), 7 (ImageLoaded),
11 (FileCreate), 13 (RegistryValueSet). Rough mix: 35/25/20/15/5.

Required fields per event_id:
  - 1: image, parent_image, command_line, integrity_level, current_directory
  - 3: image, destination_domain, destination_port, protocol,
       use_external_destination (bool)
  - 7: image, loaded_dll, dll_signed (bool)
  - 11: image, target_filename
  - 13: image, registry_key, registry_value

Always include narrative. Use real-world-looking paths
(C:\\Windows\\System32\\..., C:\\Program Files\\..., C:\\Users\\... with
literal "<USER>" as a placeholder that downstream code substitutes).
Feel free to include a rule_name that looks like
"technique_id=TXXXX,technique_name=...", but keep benign activity without
explicit MITRE tags.
"""


_LINUX_SECURE_PROMPT = """\
Generate Linux /var/log/secure scenarios for a fleet of Ubuntu servers
(web, app, db, CI, docker). Return JSON {"scenarios": [...]}.

event_type values: ssh_accept, ssh_fail, ssh_disconnect, sudo, pam_session.
Mix around: 40 / 10 / 20 / 15 / 15.

Per event_type required fields:
  - ssh_accept: auth_method ("publickey" most of the time), optional
    use_external_source=true to mark jump-box / vpn-origin logins.
  - ssh_fail: optional use_external_source=true.
  - ssh_disconnect: disconnect_reason (e.g. "disconnected by user",
    "timeout", "protocol error").
  - sudo: sudo_command (realistic ops commands - systemctl, journalctl,
    docker compose, kubectl, tail -f /var/log/syslog, etc.).
  - pam_session: session_action (opened|closed).

Narrative should describe what a realistic admin or service would be doing.
"""


_DNS_PROMPT = """\
Generate DNS query scenarios for a corporate network that browses the
public internet. Return JSON {"scenarios": [...]}.

Each scenario needs domain, query_type, reply_code. Optionally set
is_internal_domain=true for internal suffix domains (corp.local, local,
intranet), and include ttl in seconds.

Mix of query_types: mostly A, some AAAA/CNAME/MX/TXT/NS/PTR.
Mix of reply_codes: mostly NoError, occasional NXDomain, rare ServFail/Refused.

Pick domains from the real public internet (news, SaaS, APIs, CDNs, OS
update endpoints, time sync, OCSP, package mirrors, cloud providers).
Do NOT generate malicious or dictionary/DGA-looking domains - threat
campaigns produce those separately.
"""


_HTTP_PROMPT = """\
Generate HTTP access scenarios seen by an east-west/north-south proxy.
Return JSON {"scenarios": [...]}.

Per scenario: method, status, uri_path, site; optional is_internal,
user_agent, content_type, server, narrative.

Site should be either an internal DMZ host name (set is_internal=true) or
a public domain. Vary URI paths to reflect real web traffic: SaaS APIs,
static assets, health checks, SSO endpoints, webhooks, GraphQL, etc.
Include realistic Chrome / Firefox / Edge / Outlook / curl / Go-http-client
user agents.

Status mix: mostly 2xx, some 3xx, occasional 4xx, rare 5xx. Avoid
generating attack-like traffic (SQLi strings, path traversal) - those come
from campaigns.
"""


_FIREWALL_PROMPT = """\
Generate Cisco ASA syslog scenarios. Return JSON {"scenarios": [...]}.

message_id MUST be a JSON string (quoted), not an integer. Choose from:
"302013", "302014", "302015" (TCP build/teardown, UDP build),
"106023" (deny by ACL), "106100" (ACL permit),
"305011", "305012" (NAT build/tear),
"411001" (interface state), "199005" (system reloaded),
"105004" (monitor). Example: {"message_id": "302013", ...} -- never
{"message_id": 302013, ...}.

Include direction (outbound|inbound|dmz) and protocol when appropriate.
dst_port should be a sensible choice for the direction and traffic type.
acl_name optional ("outside_access_in", "dmz_access_in",
"inside_access_out", or invent realistic names).

Distribute similarly to real ASA logs: heavy on 302013/302014, light on
the rest.
"""


SOURCETYPE_PROMPTS: dict[str, str] = {
    "wineventlog": _WINEVENTLOG_PROMPT,
    "sysmon": _SYSMON_PROMPT,
    "linux_secure": _LINUX_SECURE_PROMPT,
    "stream:dns": _DNS_PROMPT,
    "stream:http": _HTTP_PROMPT,
    "cisco:asa": _FIREWALL_PROMPT,
}


def build_variation_prompt(sourcetype: str, batch_size: int) -> tuple[str, str]:
    system = _COMMON_RULES + "\n" + SOURCETYPE_PROMPTS[sourcetype]
    user = (
        f"Produce exactly {batch_size} diverse scenario objects for sourcetype "
        f"'{sourcetype}'. Respond with a single JSON object of the form "
        f'{{"scenarios": [...]}} and nothing else.'
    )
    return system, user


_CAMPAIGN_COMMON = """\
You are the *narrative planner* for a security-log threat simulator.
Given a campaign name and known indicators of compromise (IOCs), produce
an ordered multi-step plan that will be emitted across several sourcetypes
to look like the campaign in enterprise telemetry.

Rules:
- STRICT JSON only. No prose, no markdown.
- Each step must include sourcetype (wineventlog|sysmon|linux_secure|stream:dns|
  stream:http|cisco:asa) and scenario (matching that sourcetype's field rules -
  same rules as the baseline scenario prompts).
- For any step that should reference the campaign's C2 infrastructure, set
  use_c2_ip=true or use_c2_domain=true; downstream code will substitute
  the configured IOC. Never invent your own C2 IPs - the provided list is
  authoritative.
- All steps should reference the SAME victim host (use_victim_host=true
  where relevant); downstream code pins one host per campaign firing.
- Add rule_name with MITRE ATT&CK technique ids where applicable (e.g.
  "technique_id=T1071.001,technique_name=Web Protocols").
- Plan length: 4-10 steps. Order matters.

Return shape:
{
  "summary": "one-line English summary",
  "steps": [ { "sourcetype": "...", "scenario": {...}, "use_victim_host": true }, ... ]
}
"""


def build_campaign_prompt(
    campaign_id: str,
    description: str,
    iocs: dict[str, Any],
) -> tuple[str, str]:
    system = _CAMPAIGN_COMMON
    user = (
        f"Campaign: {campaign_id}\n"
        f"Description: {description}\n"
        f"Available IOCs (use via use_c2_ip / use_c2_domain flags only):\n"
        f"{json.dumps(iocs, indent=2)}\n\n"
        f"Produce a plan for one firing of this campaign."
    )
    return system, user


CAMPAIGN_DESCRIPTIONS: dict[str, str] = {
    "terndoor": (
        "Multi-stage intrusion: DLL side-loading of a signed binary, "
        "persistence via scheduled task + Run key, driver install for "
        "rootkit stealth, then HTTPS beacon to C2."
    ),
    "bruteentry": (
        "External SSH brute force from ORB infrastructure against Linux "
        "edge hosts, eventually leading to a successful login and sudo use."
    ),
    "peertime": (
        "Windows workstation beacons to three C2 domains over DNS and "
        "HTTPS on a regular interval; firewall logs the outbound sessions."
    ),
    "cobaltstrike": (
        "Cobalt Strike malleable C2 traffic: HTTPS beacon to CDN-themed "
        "domains, process injection into browser or office apps, optional "
        "SMB named-pipe lateral movement."
    ),
    "darkgate": (
        "DarkGate loader execution from an Office document, AutoHotkey "
        "script dropping, and C2 callback over HTTPS."
    ),
    "cryptojack": (
        "Linux server compromised to run an XMRig miner connecting to "
        "public mining pools; ssh accept from external IP, sudo to install "
        "miner, long-lived TCP to pool."
    ),
    "ransomsim": (
        "Ransomware precursor: mass file reads, shadow copy deletion via "
        "vssadmin, C2 check-in, and registry tampering."
    ),
    "phishkit": (
        "AiTM phishing proxy kit: user follows a link to a look-alike M365 "
        "login page; HTTP POST of credentials; subsequent legit login from "
        "attacker IP."
    ),
    "snakebyte": (
        "DNS-tunnelled C2 with periodic TXT-record lookups to attacker "
        "infrastructure, followed by HTTPS callbacks."
    ),
}
