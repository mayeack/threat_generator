// Threat hunt guidance for each campaign exposed by /api/campaigns.
// Keys MUST stay in sync with CAMPAIGN_META in threatgen/api/campaigns.py.
// Each entry provides three tiers:
//   easy   - numbered steps WITH SPL targeting sourcetypes this app emits
//            in index=threat_gen. Validated sourcetypes:
//              sysmon      -> XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
//              wineventlog -> WinEventLog:Security
//              linux_secure-> linux_secure
//              dns         -> stream:dns
//              stream:http -> stream:http
//              cisco:asa   -> cisco:asa
//            Sysmon fields are nested under EventData.* and must be quoted.
//            WinEventLog:Security lacks discrete extractions; search the
//            Message field or use rex. cisco:asa requires rex to extract
//            src_ip / dest_ip / dest_port from the message field.
//   medium - numbered steps describing the analytic WITHOUT SPL.
//   hard   - high-level PEAK-style hypotheses / pivots.
//
// Terminology should follow industry standards: MITRE ATT&CK technique IDs,
// beaconing, LOLBin, DLL side-loading, AiTM, DGA, data staging, etc.
// No hardcoded credentials, tokens, or other secrets.

window.HuntGuides = {
  terndoor: {
    summary:
      "China-nexus backdoor using DLL side-loading, msiexec process injection, scheduled-task and service persistence, a kernel driver, and port-443 C2 beaconing.",
    easy: [
      {
        title: "DLL side-loading into signed binaries (T1574.002)",
        detail:
          "Sysmon EID 7 (ImageLoad) where a signed host binary loads an unsigned DLL from a user-writable path such as AppData, ProgramData, or Temp.",
        spl:
          'index=threat_gen sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=7\n'
          + '  "EventData.Signed"="false"\n'
          + '  ("EventData.ImageLoaded"="*\\\\AppData\\\\*" OR "EventData.ImageLoaded"="*\\\\ProgramData\\\\*" OR "EventData.ImageLoaded"="*\\\\Temp\\\\*")\n'
          + '| stats count values("EventData.ImageLoaded") as dlls by Computer, "EventData.Image"\n'
          + '| sort - count',
      },
      {
        title: "msiexec spawned by an unusual parent (T1218.007)",
        detail:
          "Sysmon EID 1 where msiexec.exe is launched by a parent outside the expected Windows paths. The side-loaded WSPrint.exe under ProgramData spawning msiexec is a high-fidelity TernDoor artifact.",
        spl:
          'index=threat_gen sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1\n'
          + '  "EventData.Image"="*\\\\msiexec.exe"\n'
          + '  ("EventData.ParentImage"="C:\\\\ProgramData\\\\*"\n'
          + '   OR "EventData.ParentImage"="*\\\\AppData\\\\*"\n'
          + '   OR "EventData.ParentImage"="*\\\\Temp\\\\*"\n'
          + '   OR "EventData.ParentImage"="*\\\\Users\\\\Public\\\\*")\n'
          + '| stats count values("EventData.ParentImage") as parents values("EventData.CommandLine") as cmds by Computer',
      },
      {
        title: "Scheduled-task persistence (T1053.005)",
        detail:
          "WinEventLog Security EventCode 4698 records scheduled-task creation. Extractions are absent, so search keywords in the Message field.",
        spl:
          'index=threat_gen sourcetype="WinEventLog:Security" EventCode=4698\n'
          + '| rex field=Message "Task Name:\\s+(?<task_name>\\S+)"\n'
          + '| rex field=Message "Task Content:\\s+(?<task_cmd>[^\\n]+)"\n'
          + '| stats count values(task_cmd) as cmds by ComputerName, task_name',
      },
      {
        title: "C2 beaconing on 443 to campaign IOC set (T1071.001)",
        detail:
          "Firewall egress to TernDoor C2 IPs on 443. cisco:asa does not auto-extract IPs/ports, so use rex on the message field and bin by 1-minute buckets.",
        spl:
          'index=threat_gen sourcetype="cisco:asa" "Built outbound"\n'
          + '| rex field=message "inside:(?<src_ip>\\S+?)/\\d+.*outside:(?<dest_ip>\\S+?)/(?<dest_port>\\d+)"\n'
          + '| where dest_port="443" AND dest_ip IN ("154.205.154.82","207.148.121.95","207.148.120.52")\n'
          + '| bin _time span=1m\n'
          + '| stats dc(_time) as beats, count by src_ip, dest_ip\n'
          + '| where beats > 10',
      },
    ],
    medium: [
      {
        title: "Baseline DLL load integrity",
        detail:
          "For each signed host process, build a baseline of the DLLs it normally loads. Flag loads of unsigned DLLs from user-writable directories (AppData, ProgramData, Temp). Enrich with parent-process integrity level and signer.",
      },
      {
        title: "Detect msiexec as an injection source",
        detail:
          "msiexec should not create remote threads or open LSASS handles outside patching windows. Alert on cross-process access from msiexec.exe with suspicious GrantedAccess masks (e.g., 0x1410 / 0x1F0FFF).",
      },
      {
        title: "Audit new persistence artifacts",
        detail:
          "Watch for schtasks.exe /create, sc.exe create, and new service/driver installations correlated within a short window with any of the earlier side-loading or injection signals on the same host.",
      },
      {
        title: "Look for periodic long-running egress on 443",
        detail:
          "Even without IOCs, compute inter-arrival statistics of outbound TCP/443 sessions per (src_ip, dest_ip) pair and alert on low-variance (high periodicity) flows to rarely-seen destinations.",
      },
    ],
    hard: [
      "Hypothesis (PEAK): a signed-binary proxy execution chain is being used to load an unsigned implant, which then injects into a trusted Windows process, installs kernel-level persistence, and beacons outbound on 443. Data required: Sysmon (1, 7), WinEventLog (4698), firewall egress. Expected signal: clustered TTP sequence on a single host within minutes. Disproving criteria: the DLL load is from a signed-by-same-vendor publisher and occurs inside a legitimate installer window.",
      "Pivot: if any single host matches two of {unsigned DLL side-load, msiexec remote /i, new scheduled task, periodic 443 egress to IOC set}, treat as an APT-tier lead and pull full Sysmon timeline for the surrounding 24 hours.",
    ],
  },

  bruteentry: {
    summary:
      "ORB (Operational Relay Box) brute-force scanner targeting SSH, PostgreSQL, and Tomcat from compromised edge devices.",
    easy: [
      {
        title: "SSH password-spray from external sources (T1110.003)",
        detail:
          "linux_secure logs contain 'Failed password' messages without discrete field extractions; use rex to pull the username and source IP and aggregate by source.",
        spl:
          'index=threat_gen sourcetype=linux_secure "Failed password"\n'
          + '| rex "Failed password for (invalid user )?(?<user>\\S+) from (?<src>\\S+)"\n'
          + '| stats dc(user) as unique_users, count by src\n'
          + '| where unique_users > 5 AND count > 20\n'
          + '| sort - count',
      },
      {
        title: "PostgreSQL pg_hba rejection storm (T1110.003)",
        detail:
          "linux_secure entries from the 'postgres' process that record pg_hba.conf rejections. A single source IP generating many rejects against multiple accounts is the Postgres half of the ORB spray.",
        spl:
          'index=threat_gen sourcetype=linux_secure "pg_hba.conf reject line"\n'
          + '| rex "host all (?<user>\\S+) (?<src>\\S+?)/"\n'
          + '| stats dc(user) as unique_users count by src\n'
          + '| where count > 5\n'
          + '| sort - count',
      },
      {
        title: "Edge-service reconnaissance on auth ports (T1595.002)",
        detail:
          "cisco:asa denied / permitted inbound traffic. Extract src_ip / dest_ip / dest_port from the message field and surface external sources that touch many internal hosts on SSH / PostgreSQL / Tomcat.",
        spl:
          'index=threat_gen sourcetype="cisco:asa" ("Deny tcp" OR "Built inbound")\n'
          + '| rex field=message "outside:(?<src_ip>\\S+?)/\\d+.*(?:inside|dmz):(?<dest_ip>\\S+?)/(?<dest_port>\\d+)"\n'
          + '| where dest_port IN ("22","5432","8080","8443")\n'
          + '| stats dc(dest_ip) as targets, count by src_ip, dest_port\n'
          + '| where targets > 3\n'
          + '| sort - count',
      },
    ],
    medium: [
      {
        title: "Profile failed-auth-to-success ratio per source",
        detail:
          "Build a per-source-IP ratio of failed SSH attempts to successful logins over rolling windows. Mature brute-force operators aim for low ratios; anything that produces >20 failures then a success is worth triage.",
      },
      {
        title: "Count distinct usernames per source",
        detail:
          "High dc(username) per external src_ip is the hallmark of password spraying, independent of success. This single feature is enough to surface ORB-style scanners.",
      },
      {
        title: "Scan-fan-out heuristic",
        detail:
          "Across the firewall, alert on any single external src_ip that touches more than N internal destinations on auth-bearing ports (SSH, RDP, Postgres, Tomcat) within a short window.",
      },
    ],
    hard: [
      "Hypothesis (PEAK - baseline): residential / small-business IP space is being used as an ORB to brute-force corporate edge services. Data required: linux_secure auth outcomes, firewall edge logs. Expected signal: many low-and-slow sources, each touching many usernames and hosts. Disproving criteria: a single source is a known vulnerability scanner or pentest.",
      "Pivot: enrich surviving src_ip values with ASN, geo, and passive-DNS. Residential ASNs hitting auth ports on multiple internal hosts are the primary ORB indicator.",
    ],
  },

  peertime: {
    summary:
      "ELF backdoor using BitTorrent P2P for C2, deployed via shell scripts, Docker, and BusyBox with process masquerading as legitimate daemons.",
    easy: [
      {
        title: "BitTorrent-style peer traffic from servers (T1071.001)",
        detail:
          "cisco:asa permitted connections on BitTorrent/DHT ports (6881, 6882, 6889, 6969, 51413). A Linux server that should not be a BT peer making any outbound sessions to these ports is worth triage.",
        spl:
          'index=threat_gen sourcetype="cisco:asa" "Built outbound"\n'
          + '| rex field=message "inside:(?<src_ip>\\S+?)/\\d+.*outside:(?<dest_ip>\\S+?)/(?<dest_port>\\d+)"\n'
          + '| eval port_num=tonumber(dest_port)\n'
          + '| where port_num IN (6881,6882,6889,6969,51413)\n'
          + '| stats count values(dest_ip) as peers values(dest_port) as ports by src_ip',
      },
      {
        title: "DNS to tracker / PeerTime C2 domains (T1071.004)",
        detail:
          "stream:dns exposes queries via the multi-value field query{} which must be quoted. Hunt for tracker/announce keywords or the known PeerTime domain IOCs.",
        spl:
          'index=threat_gen sourcetype="stream:dns"\n'
          + '  ("query{}"="*tracker*" OR "query{}"="*announce*"\n'
          + '   OR "query{}"="bloopencil.net" OR "query{}"="xtibh.com" OR "query{}"="xcit76.com")\n'
          + '| stats count values("query{}") as queries by src_ip',
      },
      {
        title: "Daemon masquerading / staged loader on Linux (T1036.004)",
        detail:
          "PeerTime drops masqueraded daemons and uses BusyBox to copy them. linux_secure captures the sudo-invoked wget/curl that writes to /tmp/.cache or similar hidden paths; this is the ground-truth staging signal.",
        spl:
          'index=threat_gen sourcetype=linux_secure ("curl" OR "wget")\n'
          + '  ("/tmp/.cache/" OR "/tmp/.X11-unix/" OR "/var/tmp/.cache/" OR "/dev/shm/")\n'
          + '| rex "COMMAND=(?<cmd>.+)$"\n'
          + '| stats count values(cmd) as cmds by hostname',
      },
    ],
    medium: [
      {
        title: "Flag P2P-shaped egress from servers",
        detail:
          "Production Linux servers should have a narrow outbound profile. Alert when a server starts contacting many (>10) unique external peers in the BitTorrent port range.",
      },
      {
        title: "DNS profiling for tracker-like names",
        detail:
          "Group queries containing 'tracker', 'announce', or the campaign's C2 domains and produce a top-talkers list; pivot to flow for confirmation.",
      },
      {
        title: "Detect masqueraded daemons",
        detail:
          "Maintain an allow-list of legitimate paths for common daemon names. Alert when a process with a system-daemon name runs from an unusual path or is spawned by a shell / docker / busybox.",
      },
    ],
    hard: [
      "Hypothesis (PEAK): an adversary is using BitTorrent DHT as a C2 overlay on Linux workloads and hiding the implant as a system daemon. Data required: firewall egress, DNS, Linux auth/process telemetry. Expected signal: many-to-many peer traffic plus masqueraded daemon plus DNS to tracker-style names. Disproving criteria: a known internal mirroring or Kubernetes torrent distribution use case.",
    ],
  },

  cobaltstrike: {
    summary:
      "Cobalt Strike beacon: PowerShell download cradle, process hollowing into rundll32, named-pipe internal C2, WinRM lateral movement.",
    easy: [
      {
        title: "PowerShell download cradle (T1059.001, T1105)",
        detail:
          "Sysmon EID 1 process creations where powershell.exe runs with -encodedcommand or a download-cradle substring. Sysmon fields live under EventData.*.",
        spl:
          'index=threat_gen sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1\n'
          + '  "EventData.Image"="*\\\\powershell.exe"\n'
          + '  ("EventData.CommandLine"="*-encodedcommand*" OR "EventData.CommandLine"="*IEX*"\n'
          + '   OR "EventData.CommandLine"="*DownloadString*" OR "EventData.CommandLine"="*FromBase64String*")\n'
          + '| table _time, Computer, "EventData.User", "EventData.ParentImage", "EventData.CommandLine"',
      },
      {
        title: "rundll32 spawned from PowerShell (T1055.012)",
        detail:
          "Cobalt Strike's default hollowing target is rundll32.exe under powershell.exe. This is a high-fidelity EID 1 lead.",
        spl:
          'index=threat_gen sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1\n'
          + '  "EventData.Image"="*\\\\rundll32.exe"\n'
          + '  "EventData.ParentImage"="*\\\\powershell.exe"\n'
          + '| table _time, Computer, "EventData.User", "EventData.ParentCommandLine", "EventData.CommandLine"',
      },
      {
        title: "Named-pipe internal C2 (Cobalt defaults)",
        detail:
          "Sysmon EID 17 (PipeCreated) for Cobalt Strike's default pipe-name families (msagent_*, postex_*, status_*, MSSE-*-server).",
        spl:
          'index=threat_gen sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=17\n'
          + '  ("EventData.PipeName"="*\\\\msagent_*" OR "EventData.PipeName"="*\\\\postex_*"\n'
          + '   OR "EventData.PipeName"="*\\\\status_*" OR "EventData.PipeName"="*\\\\MSSE-*-server")\n'
          + '| stats count values("EventData.PipeName") as pipes by Computer, "EventData.Image"',
      },
      {
        title: "WinRM lateral movement (T1021.006)",
        detail:
          "Sysmon EID 3 network connections from rundll32.exe targeting WinRM ports 5985/5986 on internal hosts.",
        spl:
          'index=threat_gen sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=3\n'
          + '  "EventData.Image"="*\\\\rundll32.exe"\n'
          + '  ("EventData.DestinationPort"="5985" OR "EventData.DestinationPort"="5986")\n'
          + '| stats count by Computer, "EventData.SourceIp", "EventData.DestinationIp", "EventData.DestinationPort"',
      },
    ],
    medium: [
      {
        title: "Hunt for encoded PowerShell",
        detail:
          "Measure entropy or length of PowerShell command lines; very long or highly-random arguments plus -enc / -EncodedCommand are consistent with staging a beacon.",
      },
      {
        title: "Parent/child anomalies for rundll32",
        detail:
          "rundll32 is commonly abused. Alert when its parent is powershell / wmiprvse / office apps and when it exhibits cross-process access or network egress.",
      },
      {
        title: "Profile WinRM usage",
        detail:
          "WinRM should be confined to specific admin workstations. Alert on inbound 5985/5986 connections from source hosts outside the admin baseline.",
      },
      {
        title: "Review named-pipe creations",
        detail:
          "Build an allow-list of common pipe name prefixes in the environment and alert on creations matching Cobalt defaults or unusually short random-looking names.",
      },
    ],
    hard: [
      "Hypothesis (PEAK): a Cobalt Strike operator is staging beacons via a PowerShell cradle, hollowing into rundll32 for stealth, using named pipes for SMB-tunneled C2, and moving laterally via WinRM. Data required: Sysmon 1/3/17, firewall. Expected signal: chained TTPs on a single host and then same TTPs on a second host within minutes. Disproving criteria: matching activity tied to a known red-team engagement id.",
    ],
  },

  darkgate: {
    summary:
      "DarkGate MaaS loader delivered via malicious MSI attachments, using AutoIt scripts for execution, browser credential theft, and C2 exfiltration.",
    easy: [
      {
        title: "MSI execution from user Downloads (T1218.007, T1566.001)",
        detail:
          "Sysmon EID 1 process creations where msiexec.exe runs an MSI staged in a user's Downloads folder. Parent is usually explorer.exe.",
        spl:
          'index=threat_gen sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1\n'
          + '  "EventData.Image"="*\\\\msiexec.exe"\n'
          + '  "EventData.CommandLine"="*\\\\Downloads\\\\*.msi*"\n'
          + '| table _time, Computer, "EventData.User", "EventData.ParentImage", "EventData.CommandLine"',
      },
      {
        title: "AutoIt interpreter from AppData\\Roaming (T1059.010)",
        detail:
          "Autoit3.exe executing out of a user AppData\\Roaming subdirectory is a strong DarkGate indicator.",
        spl:
          'index=threat_gen sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1\n'
          + '  "EventData.Image"="*\\\\AppData\\\\Roaming\\\\*\\\\Autoit3.exe"\n'
          + '| table _time, Computer, "EventData.User", "EventData.Image", "EventData.CommandLine"',
      },
      {
        title: "Run-key persistence pointing at Autoit3 (T1547.001)",
        detail:
          "Sysmon EID 13 (registry SetValue) writes to HKCU\\...\\CurrentVersion\\Run whose Details field references an Autoit3.exe payload.",
        spl:
          'index=threat_gen sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=13\n'
          + '  "EventData.TargetObject"="*\\\\CurrentVersion\\\\Run\\\\*"\n'
          + '  "EventData.Details"="*Autoit3.exe*"\n'
          + '| stats count values("EventData.Details") as run_values by Computer, "EventData.TargetObject"',
      },
      {
        title: "Browser credential-store access (T1555.003)",
        detail:
          "WinEventLog Security EventCode 4663 object-access events on browser 'Login Data' / 'Cookies' SQLite files by a non-browser process (typically Autoit3.exe).",
        spl:
          'index=threat_gen sourcetype="WinEventLog:Security" EventCode=4663\n'
          + '  Message="*Login Data*" Message="*Autoit3.exe*"\n'
          + '| rex field=Message "Object Name:\\s+(?<object_name>[^\\n]+)"\n'
          + '| rex field=Message "Process Name:\\s+(?<process_name>[^\\n]+)"\n'
          + '| stats count values(process_name) as procs values(object_name) as targets by ComputerName',
      },
    ],
    medium: [
      {
        title: "Office / browser as MSI parent",
        detail:
          "msiexec legitimately runs from explorer, services, or auto-update paths. Alert when the parent is an email client, browser, or script host, or when the MSI path is under a user's Downloads folder.",
      },
      {
        title: "Hunt AutoIt in unusual locations",
        detail:
          "AutoIt3 is rarely on corporate endpoints; when present, it should be in Program Files. Alert on AutoIt executions from any user-writable directory such as AppData\\Roaming.",
      },
      {
        title: "Detect credential-store reads by non-browsers",
        detail:
          "The browser credential SQLite files should only be touched by the owning browser. Any other image reading them is a cred-harvesting lead.",
      },
      {
        title: "Outbound bulk transfer anomalies",
        detail:
          "Per user-agent and site, establish a baseline of bytes_out; alert on large POSTs or repetitive upload patterns to rare destinations.",
      },
    ],
    hard: [
      "Hypothesis (PEAK): a malspam MSI drops an AutoIt-wrapped loader that persists via a Run key, harvests browser secrets, and exfiltrates via HTTPS. Data required: Sysmon 1/13, WinEventLog 4663, HTTP egress. Expected signal: sequence of msiexec -> Autoit3.exe from AppData -> Run-key write -> browser Login Data access -> outbound HTTP burst. Disproving criteria: the MSI is signed by a known corporate vendor.",
    ],
  },

  cryptojack: {
    summary:
      "XMRig cryptominer deployed on Linux hosts via wget, cron persistence, and Stratum-protocol connections to mining pools.",
    easy: [
      {
        title: "wget / curl of miner payloads to hidden paths (T1105)",
        detail:
          "linux_secure 'sudo ... COMMAND=' entries for wget/curl writing to /tmp, /var/tmp, or /dev/shm. No discrete command field, so match the hidden-path strings in the message body.",
        spl:
          'index=threat_gen sourcetype=linux_secure ("wget" OR "curl")\n'
          + '  ("/tmp/" OR "/var/tmp/" OR "/dev/shm/")\n'
          + '| rex "COMMAND=(?<cmd>.+)$"\n'
          + '| stats count values(cmd) as cmds by hostname',
      },
      {
        title: "Cron-based miner persistence (T1053.003)",
        detail:
          "linux_secure captures crontab/crond activity. Alert on crond 'CMD' entries whose payload runs out of /tmp, /var/tmp, or /dev/shm - legitimate cron jobs should live under /usr/bin or /opt.",
        spl:
          'index=threat_gen sourcetype=linux_secure (process=crond OR process=crontab)\n'
          + '  ("/tmp/" OR "/var/tmp/" OR "/dev/shm/")\n'
          + '| stats count values(message) as cron_lines by hostname, process',
      },
      {
        title: "Stratum mining-pool egress (T1496)",
        detail:
          "cisco:asa outbound connections to classic Stratum ports (3333, 3334, 4444, 5555, 7777, 14444, 45700). Extract dest_ip/dest_port with rex.",
        spl:
          'index=threat_gen sourcetype="cisco:asa" "Built outbound"\n'
          + '| rex field=message "inside:(?<src_ip>\\S+?)/\\d+.*outside:(?<dest_ip>\\S+?)/(?<dest_port>\\d+)"\n'
          + '| where dest_port IN ("3333","3334","4444","5555","7777","14444","45700")\n'
          + '| stats count values(dest_ip) as pools by src_ip, dest_port',
      },
      {
        title: "DNS to known mining-pool names",
        detail:
          "stream:dns queries are exposed via the multi-value field query{}; quote the field name and wildcard-match common mining pool strings.",
        spl:
          'index=threat_gen sourcetype="stream:dns"\n'
          + '  ("query{}"="*pool*" OR "query{}"="*xmr*" OR "query{}"="*monero*"\n'
          + '   OR "query{}"="*nanopool*" OR "query{}"="*minexmr*")\n'
          + '| stats count values("query{}") as queries by src_ip',
      },
    ],
    medium: [
      {
        title: "Hunt tmp/ELF download patterns",
        detail:
          "Linux servers should rarely fetch binaries into /tmp/. Alert when wget/curl places ELF, tar, or xz files into user-writable directories and then executes them.",
      },
      {
        title: "Crontab diff monitoring",
        detail:
          "Track writes to /etc/cron.* and user crontabs. Any new entry that references /tmp/, /dev/shm/, or network fetches deserves triage.",
      },
      {
        title: "Profile outbound ports from servers",
        detail:
          "Most workloads do not need to reach non-web ports. Alert on egress to the common Stratum port set from any host that did not use them previously.",
      },
    ],
    hard: [
      "Hypothesis (PEAK - baseline): Linux workloads are being silently enrolled into a Monero mining pool via a wget-dropped XMRig binary persisted through cron. Data required: linux_secure, cisco:asa egress, stream:dns. Expected signal: any host with all three (payload fetch, cron write, Stratum-port egress).",
    ],
  },

  ransomsim: {
    summary:
      "Ransomware kill-chain: Volume Shadow Copy deletion, security-service termination, mass file encryption, and ransom-note dropping.",
    easy: [
      {
        title: "Volume Shadow Copy destruction (T1490)",
        detail:
          "Sysmon EID 1 process creations for vssadmin / wmic shadowcopy / bcdedit with recovery-disable arguments. These are almost exclusively pre-encryption ransomware behavior.",
        spl:
          'index=threat_gen sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1\n'
          + '  ("EventData.CommandLine"="*vssadmin*delete*shadows*"\n'
          + '   OR "EventData.CommandLine"="*wmic*shadowcopy*delete*"\n'
          + '   OR "EventData.CommandLine"="*bcdedit*recoveryenabled*"\n'
          + '   OR "EventData.CommandLine"="*wbadmin*delete*")\n'
          + '| stats count by Computer, "EventData.Image", "EventData.CommandLine"',
      },
      {
        title: "Security / backup service termination (T1489)",
        detail:
          "Sysmon EID 1 for net stop / sc stop targeting AV, EDR, VSS, SQL, or backup services. Correlate with WinEventLog 7036 service-state events.",
        spl:
          'index=threat_gen sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1\n'
          + '  "EventData.CommandLine"="net stop *"\n'
          + '  ("EventData.CommandLine"="*vss*" OR "EventData.CommandLine"="*sql*" OR "EventData.CommandLine"="*veeam*"\n'
          + '   OR "EventData.CommandLine"="*backup*" OR "EventData.CommandLine"="*sophos*" OR "EventData.CommandLine"="*memtas*"\n'
          + '   OR "EventData.CommandLine"="*mepocs*" OR "EventData.CommandLine"="*svc*")\n'
          + '| stats count values("EventData.CommandLine") as cmds by Computer',
      },
      {
        title: "Mass file encryption by extension (T1486)",
        detail:
          "Sysmon EID 11 FileCreate events for the ransomware extensions this kit uses (.locked, .encrypted, .crypted, .enc). Bin by minute to surface the encryption wave.",
        spl:
          'index=threat_gen sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=11\n'
          + '  ("EventData.TargetFilename"="*.locked" OR "EventData.TargetFilename"="*.encrypted"\n'
          + '   OR "EventData.TargetFilename"="*.crypted" OR "EventData.TargetFilename"="*.enc")\n'
          + '| bin _time span=1m\n'
          + '| stats count dc("EventData.TargetFilename") as files by _time, Computer\n'
          + '| where files > 10',
      },
      {
        title: "Ransom-note deployment (T1486)",
        detail:
          "Sysmon EID 11 FileCreate for well-known ransom-note filenames dropped on public desktops / network shares.",
        spl:
          'index=threat_gen sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=11\n'
          + '  ("EventData.TargetFilename"="*README_RESTORE*"\n'
          + '   OR "EventData.TargetFilename"="*DECRYPT_FILES*"\n'
          + '   OR "EventData.TargetFilename"="*HOW_TO_RECOVER*"\n'
          + '   OR "EventData.TargetFilename"="*HOW_TO_DECRYPT*")\n'
          + '| stats count values("EventData.TargetFilename") as notes by Computer, "EventData.Image"',
      },
    ],
    medium: [
      {
        title: "Detect shadow-copy destruction",
        detail:
          "vssadmin, wmic shadowcopy, wbadmin, and bcdedit recoveryenabled:no are strongly associated with ransomware pre-encryption. Alert on any execution of these command lines outside change windows.",
      },
      {
        title: "Baseline security-service uptime",
        detail:
          "AV/EDR services should have effectively 100% uptime. Alert on any observed stop / disable of their services on a host.",
      },
      {
        title: "High-rate file event anomaly",
        detail:
          "Per host, alert on a sharp spike in distinct file writes per minute, especially when extensions cluster on a single unusual suffix or when README/HOW_TO_DECRYPT files appear.",
      },
      {
        title: "Ransom-note artifact hunt",
        detail:
          "Any file-create whose name matches a ransom-note pattern (README*, DECRYPT*, HOW_TO_*) on a user desktop or share is a high-confidence, late-stage ransomware signal.",
      },
    ],
    hard: [
      "Hypothesis (PEAK): a ransomware operator is in the pre-encryption stage, disabling recovery, killing security tooling, and preparing to encrypt at scale. Data required: Sysmon 1/11. Expected signal: all four TTPs within a short window on the same host. Disproving criteria: backup/maintenance job correlating with a change ticket.",
      "Pivot: a single Sysmon EID 1 for vssadmin delete shadows is already actionable as a high-severity lead; do not wait for the encryption wave.",
    ],
  },

  phishkit: {
    summary:
      "Adversary-in-the-Middle (AiTM) credential-phishing proxy that captures OAuth tokens and session cookies, followed by anomalous mailbox access from the proxy's IP.",
    easy: [
      {
        title: "DNS to look-alike identity-provider domains (T1566.002)",
        detail:
          "stream:dns queries to typosquat/homoglyph variants of the identity provider. Quote query{} to address the multi-value field.",
        spl:
          'index=threat_gen sourcetype="stream:dns"\n'
          + '  ("query{}"="*login-microsoft*" OR "query{}"="*microsft*" OR "query{}"="*micros0ft*"\n'
          + '   OR "query{}"="*office365-*" OR "query{}"="*okta-*")\n'
          + '  "query{}"!="login.microsoftonline.com"\n'
          + '| stats count values("query{}") as queries by src_ip',
      },
      {
        title: "HTTP POSTs to OAuth-shaped paths on look-alike sites (T1557)",
        detail:
          "stream:http - the site field carries the requested hostname. Flag POSTs to /auth/, /login, or /common/oauth2/* on any site that is NOT the sanctioned IdP.",
        spl:
          'index=threat_gen sourcetype="stream:http" http_method=POST\n'
          + '  (uri_path="*/common/oauth2*" OR uri_path="*/token*" OR uri_path="*/auth/*")\n'
          + '  site!="login.microsoftonline.com" site!="login.okta.com"\n'
          + '| stats count values(uri_path) as paths values(status) as statuses by src_ip, site',
      },
      {
        title: "Credential-capture form POST (T1056.003)",
        detail:
          "AiTM kits relay the form body through to the IdP. The captured signal is a urlencoded POST to /common/oauth2/token on the look-alike domain returning a 302 redirect.",
        spl:
          'index=threat_gen sourcetype="stream:http" http_method=POST\n'
          + '  http_content_type="application/x-www-form-urlencoded"\n'
          + '  uri_path="*/oauth2/token*"\n'
          + '  site!="login.microsoftonline.com"\n'
          + '| stats count by src_ip, site, status',
      },
      {
        title: "Inbound mailbox access from AiTM proxy IP (T1114.002)",
        detail:
          "Adversary replays the captured session from their own infrastructure. Look for non-browser user agents (python-requests, curl) hitting OWA/EWS/Graph endpoints on the corporate mail server.",
        spl:
          'index=threat_gen sourcetype="stream:http"\n'
          + '  (http_user_agent="python-requests/*" OR http_user_agent="curl/*" OR http_user_agent="*python*")\n'
          + '  (uri_path="/owa/*" OR uri_path="/ews/*" OR uri_path="/api/v2.0/*")\n'
          + '| stats count values(uri_path) as paths by src_ip, dest_ip, site',
      },
    ],
    medium: [
      {
        title: "Newly observed look-alike domains",
        detail:
          "Maintain a list of brand strings (company name, IdP vendor). Alert on newly-resolving domains that contain a brand string but are not on the trusted domain list.",
      },
      {
        title: "OAuth endpoint anomalies",
        detail:
          "Identity-provider OAuth endpoints are hosted on a short, known set of FQDNs. Any client POSTing to OAuth-shaped paths on other hosts is an AiTM lead.",
      },
      {
        title: "Mailbox access user-agent baseline",
        detail:
          "Baseline user-agents that reach /owa, /ews, /api/v2.0. Non-browser user-agents (python-requests, curl, Go http) are a strong replay signal, especially from external source IPs.",
      },
      {
        title: "Source-IP behavior change",
        detail:
          "Flag any external source IP that FIRST hits a look-alike domain and then, within hours, hits the corporate mail server: that pair is the AiTM signature.",
      },
    ],
    hard: [
      "Hypothesis (PEAK): users are being funneled to a reverse-proxy phishing kit that harvests session cookies; attackers then replay the session from unrelated infrastructure to read mail. Data required: DNS, HTTP (or IdP logs). Expected signal: DNS to look-alike -> urlencoded POST to OAuth-shaped path -> non-browser UA accessing OWA/EWS from external IP. Disproving criteria: user on corporate VPN with approved automation tooling.",
    ],
  },

  snakebyte: {
    summary:
      "APT-style data exfiltration: SMB collection, 7-Zip archive staging, DNS tunneling with encoded subdomains, and HTTPS bulk transfer.",
    easy: [
      {
        title: "SMB share access fan-out (T1005)",
        detail:
          "WinEventLog Security EventCode 5145 records file-share access without discrete fields. rex the Source Address and Share Path out of the Message and alert on a source address touching many shares.",
        spl:
          'index=threat_gen sourcetype="WinEventLog:Security" EventCode=5145\n'
          + '| rex field=Message "Source Address:\\s+(?<src_addr>\\S+)"\n'
          + '| rex field=Message "Share Path:\\s+(?<share_path>\\S+)"\n'
          + '| stats dc(share_path) as shares, count by ComputerName, src_addr\n'
          + '| where shares > 0',
      },
      {
        title: "7-Zip / archive staging (T1560.001)",
        detail:
          "Sysmon EID 1 process creations for 7z.exe / 7za.exe / rar.exe / makecab.exe with compression arguments, typically writing to a hidden staging directory.",
        spl:
          'index=threat_gen sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1\n'
          + '  ("EventData.Image"="*\\\\7z.exe" OR "EventData.Image"="*\\\\7za.exe"\n'
          + '   OR "EventData.Image"="*\\\\rar.exe" OR "EventData.Image"="*\\\\makecab.exe")\n'
          + '  ("EventData.CommandLine"="*a *" OR "EventData.CommandLine"="*-p*"\n'
          + '   OR "EventData.CommandLine"="*.7z*" OR "EventData.CommandLine"="*.rar*")\n'
          + '| stats count values("EventData.CommandLine") as cmds by Computer, "EventData.Image"',
      },
      {
        title: "DNS tunneling via encoded subdomains (T1048.003, T1132.001)",
        detail:
          "stream:dns with TXT/CNAME/MX lookups whose left-most label is long, high-entropy, and base32-looking - a classic DNS-tunnel exfil primitive.",
        spl:
          'index=threat_gen sourcetype="stream:dns"\n'
          + '  ("query_type{}"="TXT" OR "query_type{}"="CNAME" OR "query_type{}"="MX")\n'
          + '| eval q=mvindex(\'query{}\',0)\n'
          + '| eval first_label=mvindex(split(q,"."),0)\n'
          + '| eval label_len=len(first_label)\n'
          + '| where label_len > 20\n'
          + '| stats count dc(q) as unique_q values(q) as samples by src_ip\n'
          + '| where unique_q > 5',
      },
      {
        title: "HTTPS egress from curl.exe to external IPs (T1041)",
        detail:
          "SnakeByte calls out to its C2 via curl.exe on Windows. Sysmon EID 3 from curl.exe on 443 is a high-fidelity exfil indicator.",
        spl:
          'index=threat_gen sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=3\n'
          + '  "EventData.Image"="*\\\\curl.exe"\n'
          + '  "EventData.DestinationPort"="443"\n'
          + '| stats count values("EventData.DestinationIp") as dest_ips by Computer, "EventData.Image"',
      },
    ],
    medium: [
      {
        title: "Fan-out SMB access pattern",
        detail:
          "One identity touching many file servers over SMB in a short window is either an admin inventory task or collection. Cross-reference against approved admin accounts.",
      },
      {
        title: "Archive creation on non-admin hosts",
        detail:
          "7-Zip / RAR / makecab on developer or workstation hosts that do not normally create archives is a strong staging signal, especially when output filenames are entropy-heavy or sequentially numbered.",
      },
      {
        title: "DNS tunneling heuristics",
        detail:
          "Score parent domains by (mean subdomain length, subdomain entropy, unique subdomains per hour, TXT record share). Outliers on any two of these are high-confidence tunneling leads.",
      },
      {
        title: "Outbound curl / wget from workstations",
        detail:
          "curl.exe and wget.exe are rarely used interactively on user workstations. Alert on Sysmon EID 3 from those images to any external destination.",
      },
    ],
    hard: [
      "Hypothesis (PEAK): an APT is collecting files via SMB, staging them into password-protected archives, and exfiltrating via a combination of DNS tunneling and HTTPS bulk upload through curl. Data required: WinEventLog 5145, Sysmon 1/3, stream:dns. Expected signal: the full chain (SMB fan-out -> archive creation -> tunneling + curl HTTPS egress) on or near the same host within hours. Disproving criteria: scheduled backup job or approved data-migration window.",
    ],
  },
};
