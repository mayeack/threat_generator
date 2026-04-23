# Common Hunting SPL Patterns

Reusable SPL patterns for threat hunting analysis.

---

## Data Exploration

### Assess Data Volume and Coverage
```spl
| tstats count WHERE index=* by index, sourcetype 
| sort -count
```

### Field Summary for a Sourcetype
```spl
index=<index> sourcetype=<sourcetype> 
| head 10000 
| fieldsummary 
| table field, count, distinct_count, is_exact, numeric_count, values
| sort -count
```

### Timestamp Range Check
```spl
index=<index> 
| stats min(_time) as earliest max(_time) as latest 
| eval earliest=strftime(earliest, "%Y-%m-%d %H:%M:%S")
| eval latest=strftime(latest, "%Y-%m-%d %H:%M:%S")
```

### Event Sample
```spl
index=<index> sourcetype=<sourcetype>
| head 10
| table _time, _raw
```

---

## Stack Counting (Least Frequency of Occurrence)

Core hunting technique: rare values often indicate anomalies.

### Basic LFO - Single Field
```spl
index=<index>
| stats count by <field>
| sort count
| head 20
```

### LFO with Context
```spl
index=<index>
| stats count values(src_ip) as sources dc(src_ip) as source_count by <field>
| sort count
| where count < 10
```

### Multi-field LFO
```spl
index=<index>
| stats count by <field1>, <field2>
| sort count
| head 50
```

### LFO with Time Context
```spl
index=<index>
| stats count earliest(_time) as first_seen latest(_time) as last_seen by <field>
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M")
| eval last_seen=strftime(last_seen, "%Y-%m-%d %H:%M")
| sort count
```

---

## Statistical Outlier Detection

### Z-Score Outliers (Numeric Fields)
```spl
index=<index>
| stats count as event_count by <grouping_field>
| eventstats avg(event_count) as avg_count stdev(event_count) as stdev_count
| eval z_score = round((event_count - avg_count) / stdev_count, 2)
| where z_score > 3 OR z_score < -3
| sort -z_score
```

### Interquartile Range (IQR) Outliers
```spl
index=<index>
| stats count as event_count by <grouping_field>
| eventstats perc25(event_count) as q1 perc75(event_count) as q3
| eval iqr = q3 - q1
| eval lower_bound = q1 - (1.5 * iqr)
| eval upper_bound = q3 + (1.5 * iqr)
| where event_count < lower_bound OR event_count > upper_bound
```

### Time-Based Anomalies (Hour of Day)
```spl
index=<index>
| eval hour = strftime(_time, "%H")
| stats count by user, hour
| eventstats avg(count) as avg_count stdev(count) as stdev_count by user
| eval z_score = (count - avg_count) / stdev_count
| where z_score > 2
| sort -z_score
```

---

## Temporal Analysis

### Activity Timeline
```spl
index=<index>
| timechart span=1h count by <field>
```

### First/Last Seen Analysis
```spl
index=<index>
| stats earliest(_time) as first_seen latest(_time) as last_seen count by <field>
| eval first_seen = strftime(first_seen, "%Y-%m-%d %H:%M")
| eval last_seen = strftime(last_seen, "%Y-%m-%d %H:%M")
| eval duration_days = round((latest_seen - earliest_seen) / 86400, 1)
| sort first_seen
```

### New Values Detection
```spl
index=<index> earliest=-7d latest=now
| stats earliest(_time) as first_seen by <field>
| where first_seen > relative_time(now(), "-24h")
| eval first_seen = strftime(first_seen, "%Y-%m-%d %H:%M")
| sort first_seen
```

### Baseline Deviation
```spl
index=<index> earliest=-30d
| timechart span=1d count as daily_count
| predict daily_count future_timespan=0 
| eval deviation = daily_count - predicted(daily_count)
| where abs(deviation) > 2 * stdev(daily_count)
```

---

## Behavioral Analysis

### User Baseline Deviation
```spl
index=<index>
| stats count as today_count by user
| join type=left user 
    [search index=<index> earliest=-30d latest=-1d
    | stats avg(count) as baseline_avg stdev(count) as baseline_stdev by user]
| eval z_score = (today_count - baseline_avg) / baseline_stdev
| where z_score > 3
```

### Process Ancestry Chain
```spl
index=<index> sourcetype=<endpoint_sourcetype>
| table _time, host, parent_process, process, user, cmdline
| sort _time
```

### Network Connection Beaconing
```spl
index=<index> sourcetype=<network_sourcetype>
| stats count avg(bytes_out) as avg_bytes stdev(bytes_out) as stdev_bytes by src_ip, dest_ip, dest_port
| where count > 100 AND stdev_bytes / avg_bytes < 0.1
| sort -count
```

---

## Clustering and Grouping

### Text Clustering
```spl
index=<index>
| cluster field=<text_field> showcount=true
| sort -cluster_count
| dedup cluster_label
| table cluster_label, cluster_count
```

### Event Correlation
```spl
index=<index>
| transaction <grouping_field> maxspan=5m
| stats count duration by eventcount
| sort -count
```

### Session Analysis
```spl
index=<index>
| transaction user host maxspan=30m maxpause=5m
| stats count avg(duration) as avg_session_sec dc(host) as hosts_accessed by user
| sort -hosts_accessed
```

---

## Network Hunting

### DNS Query Analysis (Tunneling Detection)
```spl
index=<dns_index>
| eval query_length = len(query)
| stats count avg(query_length) as avg_len max(query_length) as max_len by src_ip, query_type
| where max_len > 50 OR count > 1000
| sort -max_len
```

### Long Subdomain Detection
```spl
index=<dns_index>
| rex field=query "^(?<subdomain>[^.]+)\."
| eval subdomain_len = len(subdomain)
| where subdomain_len > 30
| stats count by subdomain, query, src_ip
| sort -subdomain_len
```

### Unusual Port Activity
```spl
index=<firewall_index>
| stats dc(src_ip) as unique_sources count by dest_port
| where unique_sources < 5 AND count > 100
| sort -count
```

### Outbound Connection Analysis
```spl
index=<firewall_index> action=allowed direction=outbound
| stats sum(bytes_out) as total_bytes dc(dest_ip) as unique_dests count by src_ip
| sort -total_bytes
```

---

## Endpoint Hunting

### Suspicious Process Names
```spl
index=<endpoint_index>
| rex field=process_name "(?<name_no_ext>.*)\.[^.]+$"
| stats count by process_name, name_no_ext
| where match(name_no_ext, "^(cmd|powershell|wscript|cscript|mshta|regsvr32)$")
```

### Command Line Analysis - Base64
```spl
index=<endpoint_index>
| where match(cmdline, "(?i)(base64|encodedcommand|-enc|-e )")
| table _time, host, user, process, cmdline
```

### Unsigned/Unusual Binaries
```spl
index=<endpoint_index>
| where isnull(signature) OR signature_status!="valid"
| stats count by process_path, signature_status
| sort -count
```

### Lateral Movement Indicators
```spl
index=<endpoint_index> (EventCode=4624 OR EventCode=4648)
| stats count dc(dest) as unique_targets by src_user, src_ip
| where unique_targets > 5
| sort -unique_targets
```

---

## Authentication Hunting

### Failed Login Patterns
```spl
index=<auth_index> action=failure
| stats count dc(dest) as targets by user, src_ip
| where count > 10
| sort -count
```

### Password Spray Detection
```spl
index=<auth_index> action=failure
| bin _time span=5m
| stats dc(user) as unique_users count by src_ip, _time
| where unique_users > 10
| sort -unique_users
```

### Impossible Travel
```spl
index=<auth_index> action=success
| sort user, _time
| streamstats current=f last(src_ip) as prev_ip last(_time) as prev_time by user
| where src_ip != prev_ip
| eval time_diff_min = (_time - prev_time) / 60
| iplocation src_ip
| iplocation prefix=prev_ prev_ip
| where time_diff_min < 60 AND City != prev_City
```

---

## Model-Assisted Hunting

### Built-in Anomaly Detection
```spl
index=<index>
| timechart span=1h count
| anomalydetection count action=annotate
| where isanomalous=1
```

### Density-Based Outliers
```spl
index=<index>
| stats count by <field1>, <field2>
| anomalydetection <field1> <field2> action=annotate
| where isanomalous=1
```

### Time Series Prediction
```spl
index=<index>
| timechart span=1h count
| predict count future_timespan=24 holdback=24
| eval deviation = count - predicted(count)
| where deviation > 2 * stdev(count)
```

---

## Detection Conversion

### Save as Alert (template)
```spl
index=<index> 
[hunting query logic]
| where [threshold condition]
| table _time, [key fields for investigation]
```

---

## Notable Event Creation (Splunk ES)

Generate these SPL patterns as **copyable output for the user** to paste into Splunk.
Do NOT run Notable Event creation SPL via the MCP server.

### Notable Event Field Reference

**Required fields:**

| Field | Description | Valid Values |
|-------|-------------|--------------|
| `rule_name` | Correlation search / detection name | Free text |
| `rule_title` | Display title in Incident Review | Free text |
| `rule_description` | What the detection found and why it matters | Free text |
| `security_domain` | ES security domain | `access`, `endpoint`, `network`, `threat`, `identity`, `audit` |
| `severity` | Finding severity | `critical`, `high`, `medium`, `low`, `informational` |

**Common optional fields:**

| Field | Description |
|-------|-------------|
| `src` | Source host, IP, or user |
| `dest` | Destination host or IP |
| `user` | Associated user account (destination user in most CIM models) |
| `src_user` | Source user (the acting identity, when different from `user`) |
| `dvc` | Device that observed or generated the event (sensor, proxy, EDR host) |
| `host` | Splunk `host` field; useful when it differs from `src`/`dest` |
| `orig_host` | Original host value from the raw event when normalization changes `host` |
| `process` | Process name or command line associated with the finding |
| `file_hash` | Hash (MD5/SHA1/SHA256) of a relevant file |
| `url` | URL associated with the finding |
| `signature` | Detection signature / rule ID / alert name from the source system |
| `app` | Application associated with the event (e.g., `ssh`, `okta`, `web`) |
| `orig_sid` | Search ID of the originating search (preserves link back to raw events) |
| `orig_source` | Source of the originating event (index/sourcetype/file) |
| `owner` | Analyst to assign the Notable Event to |
| `urgency` | Override urgency (`critical`, `high`, `medium`, `low`, `informational`) |
| `drilldown_name` | Label for the investigation drilldown link |
| `drilldown_search` | SPL query for analyst drilldown |
| `mitre_attack_id` | MITRE ATT&CK technique ID (e.g., `T1059.001`) |

### Entity Normalization Guardrails

Notable Events only correlate with ES Asset and Identity frameworks when entity
fields are populated in the expected format. Before `| sendalert notable`:

- **Preserve entities across aggregations.** If your hunt uses `| stats count by <something>`, the entity fields (`src`, `dest`, `user`) are dropped unless you carry them explicitly. Use `values()` or `earliest()`:
  ```spl
  | stats count values(user) as user values(src_ip) as src values(dest_ip) as dest by subdomain
  ```
  If an entity can legitimately have multiple values per finding, pick one with `earliest(user) as user` or collapse with `mvjoin(user, ",")`.
- **Normalize host vs. IP.** Asset lookups typically key off hostname. If your hunt only has IPs, add `| iplocation src` or a DNS lookup, and prefer `src_nt_host` / `dest_nt_host` where Windows hostnames are expected.
- **Separate acting and target identities.** When the event has both an actor and a target (e.g., `su`, `runas`, privilege delegation), set `src_user` for the actor and `user` for the target. Do not squash both into `user`.
- **Preserve link to raw events.** For patterns that don't pipe directly from the hunt query (Pattern 2 ad-hoc, Pattern 5 batch), include `orig_sid`, `orig_source`, and the original event `_time` when available so analysts can pivot from Incident Review back to the underlying events.

### Pattern 1: Hunt Results to Notable Events

Convert hunt query results directly into Notable Events. This is the tightest
entity-to-Notable linkage — entities propagate row-by-row from the hunt query
itself. Review the [Entity Normalization Guardrails](#entity-normalization-guardrails)
before applying, especially if `[hunting query logic]` contains `stats`/`tstats`
that could drop entity fields.

```spl
index=<index>
[hunting query logic]
| where [threshold condition]
| rename src_ip AS src, dest_ip AS dest
| eval rule_name="Hunt: [Hunt Name] - [Finding Title]"
| eval rule_title="Hunt: [Hunt Name] - [Finding Title]"
| eval rule_description="[What was found and why it matters]"
| eval security_domain="[domain]"
| eval severity="[severity]"
| sendalert notable
```

### Pattern 2: Ad-hoc Notable Event (Single Finding)

Manually escalate a single finding discovered during live hunt triage.

```spl
| makeresults
| eval rule_name="Hunt Escalation: [Finding Title]"
| eval rule_title="Hunt Escalation: [Finding Title]"
| eval rule_description="[Detailed description of the finding]"
| eval security_domain="[domain]"
| eval severity="[severity]"
| eval src="[source_host_or_ip]"
| eval dest="[dest_host_or_ip]"
| eval user="[associated_user]"
| eval owner="[analyst_name]"
| sendalert notable
```

### Pattern 3: Correlation Search Template

Saved-search-ready SPL to paste into Splunk as a scheduled correlation search.

```spl
index=<index> earliest=-<search_window> latest=now
[hunting query logic]
| where [threshold condition]
| rename src_ip AS src, dest_ip AS dest
| eval rule_name="[Detection Name]"
| eval rule_title="[Detection Name]"
| eval rule_description="[What this detects and expected impact]"
| eval security_domain="[domain]"
| eval severity=case(
    [high_severity_condition], "critical",
    [medium_severity_condition], "high",
    1==1, "medium")
| table _time, src, dest, user, rule_name, rule_title, rule_description, security_domain, severity, [additional_context_fields]
| sendalert notable
```

### Pattern 4: Notable Event with Drilldown and MITRE Context

Enriched variant with investigation drilldown and ATT&CK mapping. The drilldown
below pivots on all three primary entity fields (`src`, `dest`, `user`) so an
analyst can land on events for the exact combination that triggered the Notable.

```spl
index=<index>
[hunting query logic]
| where [threshold condition]
| rename src_ip AS src, dest_ip AS dest
| eval rule_name="[Detection Name]"
| eval rule_title="[Detection Name]"
| eval rule_description="[What this detects and expected impact]"
| eval security_domain="[domain]"
| eval severity="[severity]"
| eval mitre_attack_id="[T####.###]"
| eval drilldown_name="Investigate activity for src=".src." user=".user." dest=".dest
| eval drilldown_search="index=<index> src=\"".src."\" user=\"".user."\" dest=\"".dest."\" earliest=-24h latest=now | table _time, src, src_user, user, dest, dvc, process, action, signature"
| eval drilldown_earliest_offset="-86400"
| eval drilldown_latest_offset="0"
| sendalert notable
```

**Drilldown construction notes:**
- If any of `src`, `user`, or `dest` may be missing, guard the concatenation:
  ```spl
  | eval drilldown_search="index=<index> "
      . if(isnotnull(src),  "src=\""  . src  . "\" ", "")
      . if(isnotnull(user), "user=\"" . user . "\" ", "")
      . if(isnotnull(dest), "dest=\"" . dest . "\" ", "")
      . "earliest=-24h latest=now | table _time, src, user, dest, action"
  ```
- Provide separate drilldowns for different pivots by assigning multiple
  `drilldown_name` / `drilldown_search` pairs — ES supports a list when supplied
  via the Notable Event editor or via `savedsearches.conf` `action.notable.param.drilldown_searches`.

### Pattern 5: Batch Hunt Findings (One Notable per Finding)

Escalate all findings from a hunt in a single SPL command. Each `makeresults` block
produces one row, and `sendalert notable` fires once per row, creating exactly one
Notable Event per finding. Use this when a hunt produces multiple confirmed findings
that should all be escalated to Incident Review together.

**When to use:** The hunt is complete, findings are confirmed, and you want to
create one Notable Event per distinct finding in a single paste-and-run action.

**How it works:**
- The first finding uses `| makeresults count=1` to seed the pipeline.
- Each additional finding is added with `| append [| makeresults count=1 | eval ...]`.
- A single `| sendalert notable` at the end iterates over all rows, creating one
  Notable Event per row.
- Every row must contain the five required fields (`rule_name`, `rule_title`,
  `rule_description`, `security_domain`, `severity`) plus any relevant context fields.

```spl
| makeresults count=1
| eval rule_name="Hunt: [Hunt Name] - [Finding 1 Title]",
       rule_title="Hunt: [Hunt Name] - [Finding 1 Title]",
       rule_description="[What was found and why it matters]",
       security_domain="[domain]",
       severity="[severity]",
       src="[source]",
       dest="[destination]",
       user="[user]",
       mitre_attack_id="[T####.###]",
       drilldown_name="[Drilldown label]",
       drilldown_search="[SPL for analyst investigation]"
| append
    [| makeresults count=1
     | eval rule_name="Hunt: [Hunt Name] - [Finding 2 Title]",
            rule_title="Hunt: [Hunt Name] - [Finding 2 Title]",
            rule_description="[What was found and why it matters]",
            security_domain="[domain]",
            severity="[severity]",
            src="[source]",
            dest="[destination]",
            user="[user]",
            mitre_attack_id="[T####.###]",
            drilldown_name="[Drilldown label]",
            drilldown_search="[SPL for analyst investigation]"]
| append
    [| makeresults count=1
     | eval rule_name="Hunt: [Hunt Name] - [Finding N Title]",
            rule_title="Hunt: [Hunt Name] - [Finding N Title]",
            rule_description="[What was found and why it matters]",
            security_domain="[domain]",
            severity="[severity]",
            src="[source]",
            dest="[destination]",
            user="[user]",
            mitre_attack_id="[T####.###]",
            drilldown_name="[Drilldown label]",
            drilldown_search="[SPL for analyst investigation]"]
| sendalert notable
```

**Construction rules:**
- Add one `| append [| makeresults count=1 | eval ...]` block per finding.
- Every field assignment for a finding goes inside a single `eval` with
  comma-separated assignments so the row is self-contained.
- Include `src`, `dest`, `user`, and `mitre_attack_id` where available to enrich
  the Notable Event in Incident Review.
- When the finding came from a specific hunt search, preserve traceability by
  also setting `orig_sid` (the originating SID), `orig_source` (index/sourcetype
  the evidence came from), and the original event `_time`. Example:
  ```
  orig_sid="<hunt_search_sid>",
  orig_source="index=<index> sourcetype=<sourcetype>",
  _time=strptime("2026-04-22T14:30:00Z","%Y-%m-%dT%H:%M:%SZ")
  ```
  This lets analysts pivot from Incident Review back to the raw events, which
  is otherwise lost in the hard-coded ad-hoc patterns.
- Omit optional fields you do not have rather than setting them to empty strings.
- Test with `| table` instead of `| sendalert notable` first to verify all rows
  and fields look correct before firing.

### Pattern 6: Risk-Based Alerting (RBA)

Modern ES deployments increasingly use Risk-Based Alerting instead of (or
alongside) Notable Events. RBA attributes each finding to a risk object
(entity) and accumulates risk over time, so repeated low-severity findings
against the same entity can elevate to a Notable. Use this pattern when the
hunt output is better expressed as "add risk to these entities" than as a
direct escalation.

**Key RBA fields:**

| Field | Description | Example |
|-------|-------------|---------|
| `risk_object` | The entity value being attributed risk | `alice`, `10.1.2.3`, `host01` |
| `risk_object_type` | Type of entity | `user`, `system`, `other` |
| `risk_score` | Numeric risk to add (typical range 10–100) | `40` |
| `risk_message` | Short description surfaced in Risk Analysis | `"DNS tunneling indicators"` |
| `threat_object` | Observed threat indicator tied to the entity | domain, hash, IP |
| `threat_object_type` | Type of threat indicator | `domain`, `file_hash`, `ip_address`, `url`, `process_name` |
| `annotations.mitre_attack` | MITRE technique IDs | `T1071.004` |

**Single-entity-per-row RBA** (one row = one risk attribution; pick the single
most relevant entity per row):

```spl
index=<index>
[hunting query logic]
| where [threshold condition]
| rename src_ip AS src, dest_ip AS dest
| eval risk_object=coalesce(user, src, dest)
| eval risk_object_type=case(
    isnotnull(user), "user",
    isnotnull(src),  "system",
    isnotnull(dest), "system",
    1==1,            "other")
| eval risk_score=40
| eval search_name="Hunt: [Hunt Name] - [Finding Title]"
| eval risk_message="[What was found and why it matters]"
| eval annotations.mitre_attack="[T####.###]"
| sendalert risk param.verbose=1
```

**Multi-entity-per-finding RBA.** To attribute risk to multiple entity types from the same finding (e.g., both
the user and the source host), emit one row per entity by using `eval` +
`mvexpand`:

```spl
...prior hunt pipeline producing src, user, dest...
| eval risk_objects=mvappend(
    "user:" . user . ":40",
    "system:" . src  . ":30",
    "system:" . dest . ":20")
| mvexpand risk_objects
| rex field=risk_objects "^(?<risk_object_type>[^:]+):(?<risk_object>[^:]+):(?<risk_score>\d+)$"
| eval risk_score=tonumber(risk_score)
| eval search_name="Hunt: [Hunt Name] - [Finding Title]"
| eval risk_message="[What was found and why it matters]"
| eval annotations.mitre_attack="[T####.###]"
| sendalert risk param.verbose=1
```

**Notes:**
- `sendalert risk` requires the Splunk ES Risk Analysis adaptive response
  action to be installed (it ships with ES).
- Prefer RBA for hunt findings that are suggestive but not immediately
  actionable — the ES risk incident rules will promote accumulated risk to a
  Notable automatically.
- Combine Pattern 6 with Pattern 1/5 when a finding is both individually
  noteworthy and should contribute to entity risk: emit the Notable with
  `sendalert notable` and the risk attribution via an `append`-ed subsearch
  that ends in `sendalert risk`.
