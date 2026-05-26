---
name: peak-threat-hunting
description: Conduct threat hunts in Splunk using the PEAK framework (Prepare, Execute, Act with Knowledge). Supports hypothesis-driven, baseline, and model-assisted hunts. Use when the user wants to threat hunt, investigate security anomalies, baseline data sources, detect adversary techniques, or map findings to MITRE ATT&CK.
---

# PEAK Threat Hunting in Splunk

Guide threat hunts using the PEAK framework, executing SPL queries via the Splunk MCP server.

## Quick Start

When a user requests a threat hunt:

1. **Identify hunt type** based on their goal:
   - **Hypothesis-driven**: Hunting specific adversary behavior (e.g., "Hunt for DNS tunneling")
   - **Baseline**: Understanding normal to find anomalies (e.g., "Baseline our firewall logs")
   - **Model-Assisted (M-ATH)**: Using ML/statistical models (e.g., "Find anomalous login patterns")

2. **ALWAYS Follow the PEAK phases**: Prepare → Execute → Act

3. **Run SPL queries** using the Splunk MCP server's `run_splunk_query` tool

4. **Track progress** using the hunt checklist for the selected type

---

## MANDATORY: Plan Presentation Format

Whenever you present a plan to the user — whether it is the initial hunt plan, a revised plan after scoping, a hand-off plan, or any intermediate step labeled as a "plan" — you MUST ALWAYS structure it under the three PEAK phases:

1. **Prepare** →
2. **Execute** →
3. **Act**

### Rules for plan presentation

- The plan MUST use these three top-level headings (or numbered sections) in this exact order: `1. Prepare`, `2. Execute`, `3. Act`. Do not rename, merge, reorder, or omit any phase.
- Every actionable item in the plan MUST live under exactly one of the three phases. If an item does not fit cleanly into one phase, re-scope it until it does.
- If a phase has nothing planned yet, still include the heading and write `_(to be defined after prior phase completes)_` rather than dropping the phase.
- The arrow notation (`Prepare → Execute → Act`) MUST appear at the top of the plan as a one-line summary so the user immediately sees the PEAK flow.
- This rule applies to ALL hunt types — Hypothesis-Driven, Baseline, and Model-Assisted (M-ATH) — and to any sub-plans (e.g., a plan for just generating correlation searches still belongs under `Act`).
- Status updates, progress reports, and check-ins on an in-flight hunt MUST also reference which PEAK phase the work is currently in.

### Required plan template

```
Plan: <hunt title>
Flow: 1. Prepare → 2. Execute → 3. Act

1. Prepare
   - <preparation items: topic, research, hypothesis, ABLE, data sources>

2. Execute
   - <execution items: gather, pre-process, analyze, refine, escalate>

3. Act
   - <action items: preserve, document, detections, correlation searches,
     notable events, dashboards, communicate>
```

If you catch yourself drafting a plan that is not in this format, stop and re-render it under the three PEAK phases before sending it to the user.

## Hunt Type Selection

```
Is this topic-based or data-based?
├── Topic-based (specific behavior/threat) → Does it have implicit complexity?
│   ├── Yes (many variables, ML needed) → Model-Assisted Hunt
│   └── No (explicit detection logic) → Hypothesis-Driven Hunt
└── Data-based (understand a data source) → Baseline Hunt
```

---

## Hypothesis-Driven Hunt

Use when hunting for specific adversary behaviors or techniques.

### Phase 1: Prepare

```
Hunt Preparation Checklist:
- [ ] Topic selected and scoped
- [ ] Research completed (TTPs, threat intel)
- [ ] Hypothesis generated (testable statement)
- [ ] ABLE framework applied
- [ ] Data sources identified
- [ ] Hunt plan created
```

**1. Select Topic**: Identify the behavior to hunt (e.g., "lateral movement", "credential theft")

**2. Research Topic**: Gather threat intelligence:
- Known techniques for implementing this tactic
- Existing detections and gaps
- Threat actor TTPs (check MITRE ATT&CK)
- Prior hunts on this topic

**3. Generate Hypothesis**: Create a testable, falsifiable statement:
```
Template: "[Actor] may be [behavior] in [location] using [technique]"
Example: "An adversary may be exfiltrating data via DNS tunneling from finance endpoints"
```

**4. Apply ABLE Framework** to scope the hunt:

| Component | Question | Example |
|-----------|----------|---------|
| **A**ctor | Who/what threat? | APT group, insider, malware family |
| **B**ehavior | What TTP? | DNS tunneling, credential dumping |
| **L**ocation | Where to look? | Finance endpoints, DMZ servers |
| **E**vidence | What data/indicators? | DNS logs, unusually long queries |

**5. Check Data Availability**: Query available indexes and data:

```
Action: Run via Splunk MCP
Tool: get_indexes
Purpose: Identify available data sources
```

```
Action: Run via Splunk MCP
Tool: run_splunk_query
Query: | tstats count WHERE index=* by index, sourcetype | sort -count
Purpose: See data volume by sourcetype
```

### Phase 2: Execute

```
Hunt Execution Checklist:
- [ ] Data gathered and filtered
- [ ] Data pre-processed if needed
- [ ] Analysis techniques applied
- [ ] Hypothesis refined (if needed)
- [ ] Critical findings escalated
```

**1. Gather Data**: Collect evidence based on ABLE scope

**2. Pre-Process Data**: Ensure data quality:
- Normalize timestamps to UTC
- Filter to relevant scope
- Handle missing values

**3. Analyze**: Apply hunting techniques:

| Technique | When to Use | SPL Pattern |
|-----------|-------------|-------------|
| Stack counting (LFO) | Find rare values | `| stats count by field | sort count` |
| Frequency analysis | Find unusual patterns | `| timechart count by field` |
| Clustering | Group similar events | `| cluster field=field_name` |
| Outlier detection | Find statistical anomalies | `| eventstats avg(x) stdev(x) | eval z=(x-avg)/stdev` |

**4. Refine Hypothesis**: If initial analysis is inconclusive, adjust scope or indicators

**5. Escalate Critical Findings**: Immediately escalate confirmed malicious activity

### Phase 3: Act

```
Hunt Completion Checklist:
- [ ] Hunt preserved (queries, data, findings)
- [ ] Findings documented
- [ ] Detections created/updated
- [ ] Correlation search SPL generated (one per finding, with savedsearches.conf stanza)
- [ ] Notable Event SPL generated (if applicable)
- [ ] Dashboard created (if applicable)
- [ ] New hunt ideas logged
- [ ] Findings communicated to stakeholders
```

**1. Preserve Hunt**: Save queries, screenshots, and methodology

**2. Document Findings**: Use template in [HUNT_TEMPLATES.md](HUNT_TEMPLATES.md)

**3. Create Detections**: Convert findings to automated detection (see Detection Hierarchy below)

**4. Generate Correlation Search(es) for Findings**: For every confirmed finding that should be detected on an ongoing basis, generate a deployable correlation search using **Pattern 3 (Correlation Search Template)** in [SPL_PATTERNS.md](SPL_PATTERNS.md). Each finding produces one correlation search. Present each correlation search as copyable output that includes:

1. **The detection SPL** — the hunt query, generalized so it runs as a scheduled search (parameterized time window, threshold expressed as `where` clause, entity fields preserved, output rows limited to actionable findings).
2. **A `savedsearches.conf` stanza** — schedule (`cron_schedule`), search window (`dispatch.earliest_time` / `dispatch.latest_time`), correlation search metadata (`action.correlationsearch.enabled`, `action.correlationsearch.label`), and adaptive response actions (`action.notable`, `action.risk`, etc.).
3. **Throttling/suppression configuration** — `alert.suppress`, `alert.suppress.fields`, and `alert.suppress.period` keyed off the entity fields (`src`, `dest`, `user`) so the same entity does not trigger repeatedly within the suppression window.
4. **Severity logic** — a `case()` expression that maps observed values back to `severity` and `urgency` based on thresholds discovered during the hunt.
5. **MITRE ATT&CK annotation** — `action.notable.param.mitre_attack_id` (and/or `annotations.mitre_attack` for RBA) populated from the techniques mapped during the Prepare phase.
6. **Drilldown** — a drilldown search (Pattern 4) that pivots on `src`, `user`, and `dest` so analysts can land on the underlying events.

**Derivation procedure (hunt SPL → correlation search):**
1. Start from the SPL that produced the finding during Execute.
2. Replace any hard-coded time range with `earliest=-<search_window>` / `latest=now` matching the desired schedule cadence (typically the hunt's own observation window or shorter).
3. Add an explicit `where` threshold so only events that match the finding's criteria are returned.
4. Carry entity fields through any `stats`/`tstats` aggregations using `values()` / `earliest()` (see Entity Normalization Guardrails in [SPL_PATTERNS.md](SPL_PATTERNS.md)).
5. Append the Pattern 3 evaluation tail (`rule_name`, `rule_title`, `rule_description`, `security_domain`, `severity`, `mitre_attack_id`).
6. Test with `| table` first; only switch to `| sendalert notable` / `| sendalert risk` once row counts and field values look correct.

Do NOT run correlation search SPL via the MCP server — the user deploys it as a saved search.

**5. Generate Notable Event SPL**: When the hunt produces confirmed or high-confidence findings that warrant immediate SOC triage (rather than scheduled detection), generate SPL to create Notable Events in Splunk ES using the patterns from [SPL_PATTERNS.md](SPL_PATTERNS.md). Present the SPL as copyable output for the user to paste into Splunk. Do NOT run Notable Event creation queries via the MCP server.
- **For multiple findings (preferred):** use the batch pattern (Pattern 5: chained `makeresults` + `append` + single `sendalert notable`) to produce ONE Notable Event per finding in a single SPL command. This is the default when a hunt yields two or more findings.
- For one-off escalation of a specific finding, use the ad-hoc pattern (Pattern 2: `makeresults` + `sendalert notable`)
- For enriched pivots, use Pattern 4 (drilldown + MITRE), which pivots on `src`, `user`, and `dest` together
- **For risk attribution (suggestive-but-not-actionable findings):** use the RBA pattern (Pattern 6: `sendalert risk` with `risk_object`, `risk_object_type`, `risk_score`) so findings accumulate risk per entity and ES promotes them to Notables when risk thresholds are crossed. Combine with Pattern 1/5 when a finding should both raise a Notable and contribute to entity risk.
- **Entity fidelity:** before any `sendalert notable` or `sendalert risk`, verify the pipeline preserves entity fields (`src`, `dest`, `user`, and where applicable `src_user`, `dvc`, `process`, `file_hash`). See the Entity Normalization Guardrails section in [SPL_PATTERNS.md](SPL_PATTERNS.md) for aggregation, host-vs-IP, and actor-vs-target handling.

**Notable Event vs. Correlation Search — when to use which:**

| Use Notable Event SPL (Patterns 1, 2, 5) | Use Correlation Search (Pattern 3) |
|------------------------------------------|------------------------------------|
| One-time escalation of findings already in hand | Ongoing scheduled detection of the same behavior |
| Hunt is complete and you want findings into Incident Review now | You want future occurrences to be caught automatically |
| Run-once SPL the user pastes into Splunk | Saved search deployed with `savedsearches.conf` |

In most hunts you will produce **both**: Notable Event SPL for the findings you already confirmed, and a correlation search so that future instances of the same pattern are caught automatically.

**6. Create Dashboard**: If the hunt produced findings that warrant ongoing monitoring or analyst review (Detection Hierarchy Level 2), invoke the `splunk-dashboard-studio` skill. Pass it:

- All SPL queries used during the Execute phase (both successful and refined versions)
- The hunt hypothesis and ABLE scope (Actor, Behavior, Location, Evidence)
- Key findings: field names, notable values, thresholds discovered
- The time range used during the hunt
- Any severity classifications or risk scores identified
- Context about the target audience (SOC analysts, hunt team, management)

The subagent will design the layout, select appropriate visualizations, assemble valid Simple XML, and optionally deploy and test the dashboard on the Splunk instance.

**7. Communicate**: Share with SOC, IR, detection engineering teams. Include the generated correlation search stanzas in the handoff to the detection engineering team.

---

## Baseline Hunt

Use when establishing normal behavior for a data source to identify anomalies.

### Phase 1: Prepare

```
Baseline Preparation Checklist:
- [ ] Data source selected
- [ ] Documentation/schema researched
- [ ] Scope defined (systems, timeframe)
- [ ] Analysis plan created
```

**1. Select Data Source**: Prioritize by security relevance or coverage gaps

**2. Research Data Source**: Understand field meanings and expected values:

```
Action: Run via Splunk MCP
Tool: run_splunk_query
Query: | metadata type=sourcetypes index=<target_index> | table sourcetype, totalCount, lastTime
Purpose: Understand sourcetype coverage
```

**3. Scope**: Define system groups and timeframe (typically 30-90 days)

### Phase 2: Execute

```
Baseline Execution Checklist:
- [ ] Data gathered and filtered
- [ ] Data dictionary created
- [ ] Distributions reviewed
- [ ] Outliers investigated
- [ ] Gaps identified
- [ ] Relationships mapped
```

**1. Create Data Dictionary**: Document key fields:

```
Action: Run via Splunk MCP
Tool: run_splunk_query
Query: index=<target> | head 1000 | fieldsummary | table field, count, distinct_count, is_exact, numeric_count
Purpose: Understand field characteristics
```

**2. Review Distributions**: Establish baselines:

```spl
# Categorical field distribution
index=<target> | stats count by <field> | sort -count | head 20

# Numeric field statistics
index=<target> | stats avg(<field>) median(<field>) stdev(<field>) min(<field>) max(<field>)

# Cardinality check
index=<target> | stats dc(<field>) as unique_values
```

**3. Investigate Outliers**: Apply detection techniques from SPL_PATTERNS.md

**4. Gap Analysis**: Document missing data or quality issues

**5. Identify Relationships**: Map field correlations

### Phase 3: Act

Document baseline including:
- Data dictionary
- Statistical summaries
- Known benign outliers
- Detection candidates

**Generate Correlation Search(es) from Baseline Deviations**: For each detection candidate where the baseline produced a concrete threshold (e.g., "process X typically runs <50 times/day per host", "field Y has cardinality <10 per user"), generate a correlation search using **Pattern 3** in [SPL_PATTERNS.md](SPL_PATTERNS.md). The correlation search compares live data against the baseline thresholds and fires when deviations exceed the documented bounds. Include the same six artifacts described in the hypothesis-driven Phase 3 step 4 (detection SPL, `savedsearches.conf` stanza, throttling, severity logic, MITRE annotation, drilldown). Add the known-benign outliers from the baseline as exclusions in the search SPL so they do not generate false positives.

**Create Baseline Dashboard**: Baseline hunts are especially well suited for dashboards. Invoke the `splunk-dashboard-studio` skill to create a baseline monitoring dashboard. Pass it:
- The distribution queries (categorical, numeric, cardinality)
- The data dictionary fields and their characteristics
- Outlier thresholds discovered during the hunt
- The target index, sourcetypes, and scope
- Time range for the baseline period
The resulting dashboard gives analysts a reference view of "normal" to compare against during future investigations.

---

## Model-Assisted Hunt (M-ATH)

Use when hunting requires ML/statistical models to find complex patterns.

### Phase 1: Prepare

```
M-ATH Preparation Checklist:
- [ ] Topic selected with ML approach identified
- [ ] Research completed (methods, datasets)
- [ ] Datasets identified (labeled if supervised)
- [ ] Algorithm(s) selected
```

**Algorithm Selection Guide**:

| Goal | Algorithm Family | Splunk Approach |
|------|------------------|-----------------|
| Classify known threats | Classification | MLTK classifiers |
| Find unusual events | Anomaly detection | MLTK + `| anomalydetection` |
| Group similar events | Clustering | `| cluster` or MLTK |
| Predict future values | Time series | `| predict` |

### Phase 2: Execute

```
M-ATH Execution Checklist:
- [ ] Data gathered and preprocessed
- [ ] Model developed and refined
- [ ] Model applied to hunt data
- [ ] Results analyzed
- [ ] Critical findings escalated
```

**Key SPL for M-ATH**:

```spl
# Anomaly detection
index=<target> | anomalydetection <field> action=annotate

# Time series prediction
index=<target> | timechart count | predict count future_timespan=24

# Clustering
index=<target> | cluster field=<text_field> showcount=true
```

### Phase 3: Act

Same as hypothesis-driven, but also:
- Preserve trained models
- Document model parameters and accuracy
- Consider model-based alerting
- Invoke the `splunk-dashboard-studio` skill to create a model monitoring dashboard that tracks model outputs, anomaly scores, and prediction accuracy over time

**Correlation searches for M-ATH:** When the model produces a score or anomaly flag (e.g., `anomaly_score`, `isanomalous`, cluster outlier label), generate the correlation search around the model's scoring SPL rather than the raw hunt query. The detection SPL in Pattern 3 should:
- Apply the trained model via `| apply <model_name>` (MLTK) or re-run the scoring SPL inline
- Threshold on the model output (e.g., `where anomaly_score > 0.85` or `where isanomalous=1`)
- Carry entity fields through the model output so Notable Events / risk attribution work
- Set `severity` based on the score band (e.g., `case(anomaly_score > 0.95, "high", anomaly_score > 0.85, "medium", 1==1, "low")`)
- Schedule the correlation search no more frequently than the model's scoring cadence allows

---

## Detection Hierarchy

Convert hunt findings to automated detection. Choose the highest feasible level:

| Level | Type | When to Use | Example |
|-------|------|-------------|---------|
| 4 (Best) | **Signatures/Rules** | High confidence, low false positives | ES correlation search / Notable Event |
| 3 | **Analytics in Code** | Complex logic, needs computation | MLTK model, Python script |
| 2 | **Dashboards** | Summarized for analyst review | Daily anomaly dashboard |
| 1 (Lowest) | **Reports** | High false positives, needs expertise | Weekly outlier report |

**For Level 2 (Dashboards)**: Always invoke the `splunk-dashboard-studio` skill. It will take your hunt queries and findings and produce a validated Simple XML dashboard with appropriate visualizations, drilldown, and filtering. This is the recommended output for hunts that identify patterns requiring ongoing human review but are not yet mature enough for fully automated detection (Level 3-4).

---

## MITRE ATT&CK Integration

Map hunts to ATT&CK for coverage tracking. See [MITRE_MAPPING.md](MITRE_MAPPING.md) for technique-specific hunting guidance.

**Query ATT&CK-tagged events** (if ES is deployed):

```spl
index=notable | stats count by mitre_attack_technique_id | sort -count
```

---

## Hunt Metrics

Track these for each hunt:

| Metric | What to Record |
|--------|----------------|
| Detections created/updated | Count and IDs |
| Incidents opened | During hunt + from new detections |
| Gaps identified/closed | Data, visibility, tooling gaps |
| Vulnerabilities found | Misconfigs, missing patches |
| Techniques hunted | ATT&CK IDs covered |

See [HUNT_TEMPLATES.md](HUNT_TEMPLATES.md) for metrics tracking template.

---

## Splunk MCP Server Usage

Always use the Splunk MCP server to run queries:

```
Tool: run_splunk_query
Parameters:
  - query: SPL query string (required)
  - earliest_time: Start time (default: -24h)
  - latest_time: End time (default: now)
  - row_limit: Max results (default: 100, max: 1000)
```

**Other useful tools**:
- `get_indexes`: List available indexes
- `get_knowledge_objects`: List saved searches, alerts, macros, etc.

---

## Additional Resources

- [HUNT_TEMPLATES.md](HUNT_TEMPLATES.md) - Documentation templates
- [SPL_PATTERNS.md](SPL_PATTERNS.md) - Common hunting SPL patterns
- [MITRE_MAPPING.md](MITRE_MAPPING.md) - ATT&CK technique hunting guidance
