---
name: exposure-analytics-setup
description: Configure Splunk Enterprise Security 8 Exposure Analytics to auto-discover Assets, IPs, Users, and MAC addresses from ThreatGen events streaming into index=threat_gen. Use when the user wants to set up Exposure Analytics entity discovery, populate Asset/IP/User/MAC inventories, or validate that ThreatGen events carry the required CIM-aligned entity fields (nt_host, ip, user_id, mac).
---

# Exposure Analytics Entity Setup for ThreatGen

Wire Splunk ES 8 Exposure Analytics into a live ThreatGen stream so that every event in `index=threat_gen` auto-populates the Asset, IP, User, and MAC inventories - then validate end-to-end with the Splunk MCP server.

## When To Use

Use this skill when **all** of the following are true:

1. ThreatGen is actively streaming events into a target Splunk ES 8 instance (default assumption: `https://aisoc-shw-ac1b0ac6a138.stg.splunkcloud.com/`, `index=threat_gen`).
2. The user wants Exposure Analytics to discover entities automatically (not manual CSV uploads).
3. ThreatGen is running a build that emits the top-level entity fields `nt_host`, `ip`, `user_id`, `mac` (see [`threatgen/engine/formatters`](../../threatgen/engine/formatters) - all formatters lift these to the top level of each JSON event).

If any of the above is false, pause and fix the precondition first. Exposure Analytics is a streaming consumer; without the fields at the top level, entity inventories will stay empty.

## Invariant: every topology host must emit events as `nt_host`

Exposure Analytics's Asset inventory keys on the top-level `nt_host` field. A host that only ever appears as a destination (`dest_nt_host`, `dest_ip`, or a string inside a message) **cannot be discovered as an Asset**, no matter how many times it is referenced.

That means every entry in `threatgen/default_config.yaml` under `topology.windows_hosts`, `topology.linux_hosts`, `topology.domain_controllers`, `topology.file_servers`, `topology.dmz_servers`, and `topology.firewalls` must be the `nt_host` on at least one generator path:

| Topology bucket | Count | Generator path that emits it as `nt_host` | Source sourcetype |
|---|---|---|---|
| `windows_hosts` | 12 | `WinEventLogGenerator._host_for_event` → `random_windows_host` for 4624/4625/4634/4672/4688/4738 | `WinEventLog:Security` |
| `linux_hosts` | 8 | `LinuxSecureGenerator._render` (70% of the time) | `linux_secure` |
| `domain_controllers` | 2 | `WinEventLogGenerator._host_for_event` → `random_domain_controller` for **4768, 4769** | `WinEventLog:Security` |
| `file_servers` | 2 | `WinEventLogGenerator._host_for_event` → `random_file_server` for **5140, 5145** | `WinEventLog:Security` |
| `dmz_servers` | 6 | `LinuxSecureGenerator._render` (30% of the time via `random_dmz_server`) | `linux_secure` |
| `firewalls` | 2 | `CiscoAsaGenerator` / `firewall.py` | `cisco:asa` |
| `users` | 13 | Any generator that calls `random_user()` or `random_admin_user()` | all sourcetypes with `user_id` |

**Expected unique entity counts for the default topology:** 32 Assets, 32 MACs, 13 Users. If any of these fall short after a full compliance window, trace back to the sourcetype whose generator dropped the host — do **not** paper over the gap with a custom EA source that maps `dest_nt_host` to Asset; it produces low-fidelity records that won't match the MAC inventory.

### Validating the invariant via MCP

Run this single SPL (via `splunk_run_query`) against `index=threat_gen` with `_index_earliest=-20m` — it gives you the live count and names all in one shot:

```spl
search index=threat_gen _index_earliest=-20m earliest=-24h
| stats dc(nt_host) as distinct_hosts,
        dc(mac) as distinct_macs,
        dc(user_id) as distinct_users,
        values(nt_host) as hosts
```

Pass criteria for the default topology: `distinct_hosts=32`, `distinct_macs=32`, `distinct_users=13`. Compare `values(nt_host)` against `threatgen/default_config.yaml` topology to identify any missing host.

### Editing topology? Add a generator path first

Before adding a new host bucket to `topology` (e.g., `hypervisors`, `ot_devices`), add the helper on `Topology` (`random_<role>()`) **and** wire at least one generator to emit events with that host as `nt_host`. Without the generator path, the new host is invisible to EA.

## What Exposure Analytics Needs (cheat sheet)

Each entity discovery **source** = one saved search over an index/sourcetype that produces events containing a specific **key field**. The key field determines which inventory gets populated:

| Inventory | Required key field on the event |
|---|---|
| Asset | `nt_host` |
| IP | `ip` |
| User | `user_id` |
| MAC | `mac` |

Source **type** dictates the search constraints:

| Source type | Refresh | Event search constraint |
|---|---|---|
| `streaming` | On a compliance window (seconds) | **Cannot** contain `\|` - must be a pure base search relying on indexed fields |
| `scheduled` | On a cron-like interval | Can contain `\|` and complex SPL |
| `static` | One-off file upload | N/A |

Because ThreatGen sends JSON and the TA sets `KV_MODE=json`, every top-level key becomes an indexed-like field at search time. That means ThreatGen's seven sourcetypes all qualify as `streaming` sources - no pipes needed.

Source **category** is picked from the wizard dropdown, which exposes: `Logs`, `Database`, `DHCP`, `Network`, `Cloud`, `VPN`, `Firewall`, `Filter`, `Malware`, `Encryption`, `Asset`, `Identity`, `Vulnerability`. Pick one per source; ThreatGen's sourcetypes split as:

| Sourcetype | Category |
|---|---|
| `WinEventLog:Security` | Logs |
| `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Logs |
| `linux_secure` | Logs |
| `stream:dns` | Network |
| `stream:http` | Network |
| `cisco:asa` | Firewall |

## Workflow

The agent runs this end-to-end, checking in with the user only at the UI step (which the agent cannot drive directly) and at the final summary.

```
1. Preflight (MCP) → 2. UI config → 3. Post-setup verify (MCP) → 4. Report
```

---

## Step 1 - Preflight via Splunk MCP

Before touching the UI, confirm the data is landing and the key fields are actually extracted. Run each of these with the `user-splunk-mcp-server` MCP server using the `splunk_run_query` tool. Use a 15-minute window unless the user specifies otherwise.

### 1a. Confirm the index is populating

```spl
search index=threat_gen earliest=-15m | stats count by sourcetype
```

**Pass criteria:** Non-zero counts for at least `WinEventLog:Security`, `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, `linux_secure`, `stream:dns`, `stream:http`, `cisco:asa`. If a sourcetype is missing, stop and ask the user to enable that generator in ThreatGen before proceeding.

### 1b. Confirm the four key fields extract

Run one query per key field per sourcetype. The agent should report any that return zero rows as a blocker.

Asset (`nt_host`):

```spl
search index=threat_gen earliest=-15m nt_host=* | stats count by sourcetype
```

IP (`ip`):

```spl
search index=threat_gen earliest=-15m ip=* | stats count by sourcetype
```

User (`user_id`):

```spl
search index=threat_gen earliest=-15m user_id=* | stats count by sourcetype
```

MAC (`mac`):

```spl
search index=threat_gen earliest=-15m mac=* | stats count by sourcetype
```

**Pass criteria:** `nt_host` present on all endpoint sources (WinEventLog, Sysmon, linux_secure), `ip` present on network sources (stream:dns, stream:http, cisco:asa), `user_id` present on auth-bearing sourcetypes (WinEventLog, Sysmon, linux_secure, and - thanks to ThreatGen's top-level promotion - stream:dns and stream:http), `mac` present on every sourcetype.

### 1c. Spot-check a raw event for each key sourcetype

Pull one raw event per sourcetype and confirm the top-level JSON keys are actually present (not buried in `EventData` or `message`):

```spl
search index=threat_gen sourcetype="WinEventLog:Security" nt_host=* user_id=* | head 1
search index=threat_gen sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" nt_host=* | head 1
search index=threat_gen sourcetype=linux_secure user_id=* | head 1
search index=threat_gen sourcetype="stream:dns" ip=* mac=* | head 1
search index=threat_gen sourcetype="stream:http" ip=* mac=* | head 1
search index=threat_gen sourcetype="cisco:asa" src_ip=* | head 1
```

If any query returns zero rows, treat it as a blocker. See the **Troubleshooting** section below.

### 1d. Confirm topology coverage (the invariant)

Verify all 32 topology hosts, 32 MACs, and 13 users are observed as `nt_host` / `mac` / `user_id`:

```spl
search index=threat_gen _index_earliest=-20m earliest=-24h
| stats dc(nt_host) as distinct_hosts,
        dc(mac) as distinct_macs,
        dc(user_id) as distinct_users,
        values(nt_host) as hosts
```

**Pass criteria:** `distinct_hosts=32`, `distinct_macs=32`, `distinct_users=13` for the default topology. If any bucket is short, cross-reference the `values(nt_host)` list against `threatgen/default_config.yaml` topology. Missing DCs / file servers → verify `WinEventLog:Security` events with `EventCode IN (4768, 4769, 5140, 5145)` are present:

```spl
search index=threat_gen _index_earliest=-20m earliest=-24h sourcetype="WinEventLog:Security" EventCode IN (4768, 4769, 5140, 5145)
| stats count by EventCode, nt_host
```

Missing DMZ hosts → verify `linux_secure` rolls DMZ ~30% of the time:

```spl
search index=threat_gen _index_earliest=-20m earliest=-24h sourcetype=linux_secure
| stats count by nt_host
```

If the new event codes (4768/4769/5140/5145) are absent and the ThreatGen build predates this skill, refresh the LLM cache (`POST /api/llm/refresh`) and re-enter the generator loop. New codes require the `event_code` enum in `threatgen/engine/llm/schemas.py` to include them.

---

## Step 2 - UI configuration in Splunk ES 8

The agent cannot drive the UI directly, so **emit the following numbered checklist back to the user** and ask them to execute it in the ES 8 app at their Splunk Cloud URL. Reference the admin guide: [Exposure Analytics set-up guide](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/exposure-analytics/exposure-analytics-set-up-guide-for-admins-in-splunk-enterprise-security).

### 2a. Open the Exposure analytics app

1. Log in to the ES 8 UI.
2. In the top navigation bar, click **Configure** → **Exposure analytics**.
   - Direct URL shortcut: `/app/SplunkEnterpriseSecuritySuite/ess_configuration/#/exposure_analytics/entity_discovery_sources`
3. You land on the Exposure analytics section with a left-hand sidebar containing:
   - **Entity discovery sources** (where sources are added and toggled on/off)
   - **Configuration settings** (Processing searches / Default configurations / UI preferences / Data deletion tabs)
   - **Inventory management**
   - **Inventory enrichment**
   - **Filter management**
4. If a **Set up exposure analytics** splash screen appears in the main pane with a **Setting up...** button and a progress row (`Initial → Data migration → Refresh configurations → Finalizing installation → Done`), click it and let the installer reach **Done** before proceeding. No user choices are required in this step; it provisions the backing lookups and jobs.
5. Once provisioning completes, the **Entity discovery sources** page starts empty - it just shows a single tile titled **Add sources** with an **Add** button on the right. Predefined sources are not pre-populated; every source (predefined template or fully custom) is created by clicking **Add**.

### 2b. Configuration settings (left sidebar)

Click **Configuration settings** in the left sidebar. The page has four tabs along the top:

- **Processing searches** (default) - master on/off switches for each entity type and for cross-cutting jobs.
- **Default configurations** - global defaults used when new sources are created.
- **UI preferences** - cosmetic/display options (Entity discovery view defaults, common country selection).
- **Data deletion** - destructive reset/delete actions for discovered inventories, sources, filters, enrichment rules, and the subnet directory.

#### 2b-i. Confirm processing searches are On (required)

On the **Processing searches** tab, under **Entity discovery**, every toggle should be **On**:

- Assets
- IP addresses
- Users
- MAC addresses

Under **Other** the same applies:

- Asset and user associations
- Recently seen sourcetypes (you can click **Run** after sources are added to prime the sourcetype catalog)

These are the scheduled jobs that consume events from every **Entity discovery source** and write rows into the Asset / IP / User / MAC inventories. If any of them is Off, discovery will not happen regardless of how many sources you add.

#### 2b-ii. Data source indexes (check scope)

On the **Default configurations** tab, locate the **Data source indexes** row and click **Edit**. This list defines which indexes processing searches are allowed to read. Confirm `threat_gen` (and `*` if that is the default) is included. If `threat_gen` is missing and the list is not `*`, add it and Save, otherwise no custom source will be able to find events.

The other Default configurations controls - **Enrichment rules (all inventories)**, **Edit field priorities**, **Federated transparent mode compatibility**, **Asset types**, **User types**, **Ephemeral assets and users** - can be left at their defaults on first run.

### 2c. Inventory enrichment - Subnet directory (recommended)

In the left sidebar, click **Inventory enrichment**, then select the **Subnet directory** tab (other tabs on the same page: **Enrichment rules**, **Enrichment lookups**).

Click **+ Add** to open the `Add subnet entry` modal. The modal has these fields (order as shown in the UI): `subnet`, `location_id`, `bunit`, `environment`, `description`, `provider`, `city`, `state`, `country`, `region`, `type`, `priority` (dropdown), `vlan`. All fields except `subnet` are optional; `priority` is a dropdown, everything else is free text.

There is no separate "Company-owned" toggle - presence in the subnet directory itself is what marks a CIDR as known/company. Create one entry per ThreatGen CIDR with the values below; leave any unspecified field blank.

| subnet | location_id | bunit | environment | description | type | priority |
|---|---|---|---|---|---|---|
| `10.1.0.0/16` | `corp-hq` | `corp` | `production` | ThreatGen internal corp endpoints and servers | `internal` | `medium` |
| `172.16.1.0/24` | `dmz` | `dmz` | `production` | ThreatGen DMZ | `dmz` | `high` |
| `203.0.113.0/24` | `perimeter` | `perimeter` | `production` | ThreatGen NAT / perimeter | `perimeter` | `high` |

Click **Save** after each entry. The directory also accepts `priority` values from the dropdown - pick the one that best matches from the options offered (common values: `low`, `medium`, `high`, `critical`).

If this modal looks different in your build, fill in at least `subnet` and `description` - those two are sufficient to register the CIDR. The other fields are enrichment metadata and do not block discovery.

### 2d. Entity discovery sources (required)

1. In the left sidebar, click **Entity discovery sources**. The page starts with only a single **Add sources** tile and an **Add** button on the right.
2. Click **Add** to open the source-creation wizard. The wizard has two top-level tabs: **Predefined** and **Additional** (predefined templates vs. custom sources).

#### 2d-i. Predefined templates that apply to ThreatGen

Four ThreatGen sourcetypes have matching predefined templates. Add these from the **Predefined** tab first; Validate before saving and keep only the ones whose key-field presence is non-zero:

| Predefined name (page) | Nickname / sourcetype | ThreatGen coverage | Watch-out |
|---|---|---|---|
| Microsoft - Windows Security Auth (Kerberos) (page 3) | `WinSecurity` / `WinEventLog` | `WinEventLog:Security` (logon / Kerberos) | Strict EventCode filter; validate before save |
| Microsoft - Sysmon (page 4) | `WinSysmon` / `XmlWinEventLog` | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Should validate as-is |
| Linux - SSHD Auth Events (page 2) | `Linux_sshd` / `linux_secure` | `linux_secure` | Should validate as-is |
| Cisco - ASA VPN Sessions (page 1) | `Cisco_ASA_VPN` / `cisco:asa` | `cisco:asa` VPN events only | ThreatGen mainly emits connection events (`%ASA-6-302*`), not VPN. Expect low / zero validation - still add the custom source below to cover non-VPN ASA. |

Other predefined variants on pages 3-4 (**Windows Security Auth (NTLM)**, **Windows Security Unlock Events**, XmlWinEventLog variants) can be added if their Validate step shows non-zero coverage; otherwise skip.

No predefined template exists for `stream:dns` or `stream:http` - those two must be custom.

#### 2d-ii. Custom sources (Additional tab) for the remaining sourcetypes

For any sourcetype that has no predefined template, or whose predefined template validated at 0%, add a custom source from the **Additional** tab. The custom wizard is a 4-step flow:

1. **Define source** (type banner "Streaming data source events - Events indexed into Splunk as soon as they are logged" confirms this is a streaming source):
   - **Vendor** (required, free text): `threatgen`
   - **Category** (required, dropdown): one of `Logs`, `Database`, `DHCP`, `Network`, `Cloud`, `VPN`, `Firewall`, `Filter`, `Malware`, `Encryption`, `Asset`, `Identity`, `Vulnerability`. Use the value in the table below.
   - **Label** (required, free text): human-friendly name (e.g., `ThreatGen - WinEventLog Security`)
   - **Nickname** (required, free text, no spaces): short identifier used internally (e.g., `threatgen-wineventlog-security`)
   - **Data source is passive** (toggle): **Off**. ThreatGen is actively streaming.
   - Click **Next**.
2. **Search events** - enter the event search exactly as shown in the table (no pipes). Click **Next**.
3. **Select entities** - toggle each discovery type On. Exposure Analytics hard-codes the field mappings: `Asset` = `nt_host`, `IP` = `ip`, `User` = `user_id`, `MAC` = `mac`. Turn on all four for ThreatGen endpoint/network sources (for `cisco:asa` leave User off since ASA events don't carry a user_id). The chosen set is stored on the source and shown as badges (`Asset` `IP` `User` `MAC`) in the header of the source's Edit modal afterwards.
4. **Validate** - check that each selected key field shows non-zero presence. The Field summary table lists *all* asset/IP/user/MAC enrichment fields EA recognizes, not just the key field; only rows marked `Required` (the key field - e.g., `nt_host` for Asset) must show `Values found = ✓`. The other enrichment rows (bunit, city, cpu_cores, etc.) are optional metadata and are expected to be `X` for synthetic ThreatGen data. Click **Save**.

> **UI note:** after Save, re-opening the source shows an Edit modal with tabs `Details / Search / Priorities / Validate / Other`. The Add-wizard's "Select entities" step has no editable analog in Edit mode - the chosen entity types are shown only as read-only badges in the modal header. The **Other** tab contains only `Max window` (default 1 Day), not entity toggles. If you need to flip an entity type off, delete and re-create the source.

Custom source values:

| Label | Nickname | Category | Vendor | Event search (Step 2) | Key fields (Step 3) |
|---|---|---|---|---|---|
| ThreatGen - Cisco ASA (non-VPN) | `threatgen-cisco-asa` | Firewall | threatgen | `index=threat_gen sourcetype="cisco:asa"` | `ip, nt_host, mac` |
| ThreatGen - Stream DNS | `threatgen-stream-dns` | Network | threatgen | `index=threat_gen sourcetype="stream:dns"` | `ip, nt_host, user_id, mac` |
| ThreatGen - Stream HTTP | `threatgen-stream-http` | Network | threatgen | `index=threat_gen sourcetype="stream:http"` | `ip, nt_host, user_id, mac` |

If any predefined template from 2d-i failed validation, add a custom equivalent from this table:

| Label | Nickname | Category | Vendor | Event search | Key fields |
|---|---|---|---|---|---|
| ThreatGen - WinEventLog Security | `threatgen-wineventlog-security` | Logs | threatgen | `index=threat_gen sourcetype="WinEventLog:Security"` | `nt_host, user_id, ip, mac` |
| ThreatGen - Sysmon | `threatgen-sysmon` | Logs | threatgen | `index=threat_gen sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"` | `nt_host, mac, user_id, ip` |
| ThreatGen - Linux secure | `threatgen-linux-secure` | Logs | threatgen | `index=threat_gen sourcetype=linux_secure` | `nt_host, user_id, ip, mac` |

3. After all predefined + custom sources exist, each row on the Entity discovery sources page should show **Status = On**. If a newly created source defaults to Off, toggle it On and Save.

References: [Add an additional source](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/exposure-analytics/configuring-entity-discovery-sources-for-exposure-analytics/add-a-source-in-exposure-analytics/add-an-additional-source), [Create or modify an event search](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/exposure-analytics/configuring-entity-discovery-sources-for-exposure-analytics/edit-a-source-in-exposure-analytics/create-or-modify-an-event-search).

### 2e. Inventory enrichment - additional fields (optional)

Beyond the subnet directory, **Inventory enrichment** also lets you layer fields like `bunit`, `priority`, or `category` onto discovered entities. For synthetic ThreatGen data this can be skipped on first run.

### 2f. Filter management (optional)

In the left sidebar, **Filter management** is used to exclude noisy hosts/users from discovery. Skip on first run; revisit once real detections are firing.

### 2g. Activate sources

On **Entity discovery sources**, confirm every source created in 2d (predefined + custom) shows **Status = On**. If any defaulted to Off after creation, toggle it On and Save. Exposure Analytics will begin populating the inventories on the next compliance window (≤ 5 minutes with the default settings).

---

## Step 3 - Post-setup validation via Splunk MCP

Give Exposure Analytics at least **two compliance windows (≈10 minutes)** after activation, then run these checks.

### 3a. Confirm the backing KV store collections exist

Run `splunk_get_kv_store_collections` via MCP. Look for (names may vary slightly by ES version):

- `cim_asset_identities_lookup` (or `asset_lookup_by_str`) - Asset inventory
- `cim_ip_lookup` - IP inventory
- `cim_user_lookup` - User inventory
- `cim_mac_lookup` - MAC inventory

If any are missing, Exposure Analytics hasn't been activated at the app level; re-check Step 2g.

### 3b. Confirm entities are being written

Run these SPL searches (via `splunk_run_query`). For first-boot validation, expect non-empty results within 10 minutes:

```spl
| inputlookup asset_lookup_by_str | search nt_host=WS-* OR nt_host=lnx-* OR nt_host=asa-* OR nt_host=dmz-* | stats count by nt_host | head 20
```

```spl
| inputlookup cim_ip_lookup | search ip IN (10.1.*, 172.16.1.*, 203.0.113.*) | stats count by ip | head 20
```

```spl
| inputlookup cim_user_lookup | search user_id=* | stats count by user_id | head 20
```

```spl
| inputlookup cim_mac_lookup | search mac="02:*" | stats count by mac | head 20
```

**Pass criteria:** each returns a non-zero number of ThreatGen-shaped rows (the MAC check specifically filters on the `02:` locally-administered prefix ThreatGen uses for deterministic host MACs). If a lookup name doesn't resolve, check the ES 8 Settings → Lookups page for the actual name used by this install and re-run.

### 3c. Spot-check the UI (user-driven)

Ask the user to open **Analytics → Entity discovery** (top nav) and toggle the `Entity type` dropdown through `Assets`, `IPs`, `Users`, and `MACs` to confirm each view shows populated rows within ≤10 minutes. Record the counts they see for the final report.

---

## Step 4 - Agent report

At the end of the run, emit a concise summary back to the user containing:

1. Preflight results (counts of events with each of the 4 key fields, per sourcetype).
2. UI configuration status: predefined sources enabled, additional streaming sources created, compliance window, activation status.
3. Post-setup inventory counts (assets / IPs / users / MACs).
4. A final checklist (copy-paste ready) the user can save for re-validation:

```
[ ] index=threat_gen receiving events (all 6 sourcetypes)
[ ] nt_host / ip / user_id / mac extracted on every sourcetype
[ ] Topology coverage: distinct(nt_host)=32, distinct(mac)=32, distinct(user_id)=13
    [ ] WinEventLog:Security emits EventCode IN (4768, 4769) from both domain controllers
    [ ] WinEventLog:Security emits EventCode IN (5140, 5145) from both file servers
    [ ] linux_secure emits nt_host=dmz-* for all 6 DMZ hosts
[ ] Configure -> Exposure analytics -> Entity discovery sources contains, at minimum:
    [ ] Predefined: Microsoft - Windows Security Auth (Kerberos) (WinSecurity) -- validated > 0%
    [ ] Predefined: Microsoft - Sysmon (WinSysmon) -- validated > 0%
    [ ] Predefined: Linux - SSHD Auth Events (Linux_sshd) -- validated > 0%
    [ ] Custom: threatgen-cisco-asa (covers non-VPN ASA; add Cisco - ASA VPN Sessions too if validated)
    [ ] Custom: threatgen-stream-dns
    [ ] Custom: threatgen-stream-http
    [ ] Custom fallbacks added for any predefined that validated at 0%
[ ] Every entity discovery source row shows Status=On
[ ] Configure -> Exposure analytics -> Configuration settings -> Processing searches: Assets / IP addresses / Users / MAC addresses / Asset and user associations / Recently seen sourcetypes all On
[ ] Configure -> Exposure analytics -> Inventory enrichment -> Subnet directory contains 10.1.0.0/16, 172.16.1.0/24, 203.0.113.0/24 (company-owned)
[ ] Configure -> Exposure analytics -> Configuration settings -> Default configurations -> Data source indexes includes threat_gen (or is wildcard)
[ ] Analytics -> Entity discovery shows populated Assets / IPs / Users / MACs within 10 min
```

---

## Troubleshooting

Symptom → Most likely cause → Fix.

- **Events are in the index but Exposure Analytics inventories stay empty**
  - Cause: Key field (`nt_host` / `ip` / `user_id` / `mac`) is not extracted at the top level.
  - Fix: From Splunk UI run `search index=threat_gen sourcetype=<sourcetype> | fieldsummary | search field IN (nt_host, ip, user_id, mac)`. If a field shows `count=0`, the ThreatGen build predates this skill; pull the latest, restart the generator, and wait one compliance window.

- **Asset inventory is populated but a subset of topology hosts is missing (e.g., DCs, file servers, DMZ servers)**
  - Cause: The topology host is only ever referenced as `dest_nt_host` or embedded in a message — no generator path emits it as `nt_host`.
  - Fix: Add/confirm the generator path per the **Invariant** table at the top of this skill. Specifically:
    - Domain controllers need `WinEventLogGenerator` to emit EventCode 4768/4769 (`_kerberos_tgt`, `_kerberos_service` handlers).
    - File servers need `WinEventLogGenerator` to emit EventCode 5140/5145 (`_share_access`, `_share_detail` handlers).
    - DMZ servers need `LinuxSecureGenerator._render` to call `random_dmz_server()` on ~30% of events.
  - After code changes, trigger `POST /api/llm/refresh` (the LLM scenario cache must be rebuilt so it can produce scenarios with the new event codes) and `POST /api/generator/start` to re-enter the event loop.

- **UI "Validate" on a custom source returns "key field not found"**
  - Cause: The source's event search does not match events that actually carry the key field, or `KV_MODE=json` is not applied.
  - Fix: Confirm the TA `splunk/TA-threat_gen/default/props.conf` stanza for that sourcetype has `KV_MODE = json` and `INDEXED_EXTRACTIONS = json` (if on a Universal Forwarder). Rebuild/redeploy the TA if needed.

- **`mac` field is empty on a subset of events**
  - Cause: That event path doesn't have a host in scope (e.g., Sysmon ImageLoaded / RegistryValueSet don't bind a user). That is expected and not a blocker as long as every *host-originating* event type carries `mac`.

- **Streaming source rejected with "search contains pipe"**
  - Cause: You typed a post-processing `|` into the event search.
  - Fix: Remove all pipes; streaming sources must be pure base searches. If you need post-processing (e.g., calculated fields), convert the source type to `scheduled`.

- **Duplicate assets in the inventory**
  - Cause: Case-mismatch between `nt_host` on different sourcetypes (e.g., `WS-PC01` vs `ws-pc01`).
  - Fix: ThreatGen normalizes hostnames via `topology.fqdn`; verify no upstream transform is lowercasing. If needed, add a `FIELDALIAS` or an **Inventory enrichment** rule in Step 2e.

---

## References

- [Exposure Analytics set-up guide for admins](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/exposure-analytics/exposure-analytics-set-up-guide-for-admins-in-splunk-enterprise-security)
- [Entity discovery source categories](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/exposure-analytics/configuring-entity-discovery-sources-for-exposure-analytics/entity-discovery-source-categories)
- [Exposure Analytics source types](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/exposure-analytics/configuring-entity-discovery-sources-for-exposure-analytics/entity-discovery-source-categories/exposure-analytics-source-types)
- [Add an additional source in Exposure Analytics](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/exposure-analytics/configuring-entity-discovery-sources-for-exposure-analytics/add-a-source-in-exposure-analytics/add-an-additional-source)
- [Create or modify an event search](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/exposure-analytics/configuring-entity-discovery-sources-for-exposure-analytics/edit-a-source-in-exposure-analytics/create-or-modify-an-event-search)
- [Asset and identity fields after processing in Splunk Enterprise Security](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/asset-and-identity-validation/asset-and-identity-fields-after-processing-in-splunk-enterprise-security)
