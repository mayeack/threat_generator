---
description: Keep threatgen/static/js/hunt-guides.js synchronized with the threat-campaign catalog. Every campaign add/modify/remove must update the guide in the same change.
globs: "threatgen/api/campaigns.py,threatgen/default_config.yaml,threatgen/engine/threats/**/*.py,threatgen/static/js/hunt-guides.js,threatgen/static/js/campaigns.js"
alwaysApply: true
---

# Campaign Hunt Guide Maintenance (ThreatGen)

`threatgen/static/js/hunt-guides.js` is the source of the "How to Detect"
guidance rendered by the campaign modal on the Campaigns page. It is a
first-class part of the campaign catalog, not a cosmetic extra. Whenever you
add, modify, remove, or rename a threat campaign anywhere in the codebase,
you must update the corresponding guide entry **in the same change/commit**.
A pull request that alters the campaign catalog without updating
`hunt-guides.js` is incomplete.

## Canonical sources

1. **`CAMPAIGN_META` in `threatgen/api/campaigns.py`** is the canonical
   campaign catalog. Every key here must exist as a top-level key in
   `window.HuntGuides` in `threatgen/static/js/hunt-guides.js`, and nothing
   else may exist there. Orphan guide entries are not permitted.
2. The `threat_campaigns` block in `threatgen/default_config.yaml` and the
   generator modules under `threatgen/engine/threats/` must stay aligned
   with `CAMPAIGN_META`.

## Golden Rules

1. **Every campaign change is a guide change.** Adding, removing, or
   renaming a campaign id requires the matching add / remove / rename in
   `hunt-guides.js` in the same change.
2. **All three tiers are required.** Every guide entry must provide
   `easy` (steps WITH SPL), `medium` (steps WITHOUT SPL), and `hard`
   (high-level PEAK-style hypotheses). Dropping a tier is not permitted.
3. **Keep MITRE citations honest.** When a campaign's `mitre_techniques`
   list changes, revise the guide so every `easy` / `medium` step cites an
   ATT&CK technique ID that still appears on the card, and update `hard`
   hypotheses to reference the current technique set.
4. **Keep SPL anchored to real telemetry.** When IOC field sets
   (`c2_ips`, `c2_domains`, `orb_ips`, `mining_pools`, `phish_domains`,
   `proxy_ips`, etc.) or the generator modules under
   `threatgen/engine/threats/*.py` change the sourcetypes, EventCodes, or
   field names they emit, update the easy-tier SPL to match. Target
   `index=threat_gen` and the real Splunk sourcetypes the HEC forwarder
   assigns:
   - `sysmon` -> `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
     (fields are nested, reference them as `"EventData.Image"`,
     `"EventData.CommandLine"`, `"EventData.ImageLoaded"`,
     `"EventData.TargetFilename"`, `"EventData.TargetObject"`,
     `"EventData.Details"`, `"EventData.PipeName"`,
     `"EventData.DestinationIp"`, `"EventData.DestinationPort"`, etc.;
     use `EventID=<n>` not `EventCode`).
   - `wineventlog` -> `WinEventLog:Security` (no discrete field
     extractions; search `Message` with keywords or use `rex`. Host is
     in `ComputerName`).
   - `linux_secure` -> `linux_secure` (`hostname`, `process`, and a
     free-form `message` field; extract fields with `rex`).
   - `dns` -> `stream:dns` (multi-value fields must be quoted, e.g.
     `"query{}"`, `"query_type{}"`, `"host_addr{}"`).
   - `http` -> `stream:http` (`src_ip`, `dest_ip`, `site`, `uri_path`,
     `http_method`, `http_user_agent`, `http_content_type`, `bytes_out`
     are directly queryable).
   - `firewall` -> `cisco:asa` (no auto-extractions; use `rex` on the
     `message` field to pull `src_ip`, `dest_ip`, and `dest_port` out
     of `inside:<ip>/<port> ... outside:<ip>/<port>` segments).
   Every easy-tier query should be runnable against a live Splunk and
   return non-empty results on a populated `index=threat_gen`.
5. **Use industry-standard terminology.** Guide copy should use MITRE ATT&CK
   technique IDs (e.g. `T1055`, `T1574.002`), and standard terms such as
   "beaconing", "LOLBin", "DLL side-loading", "AiTM", "DGA",
   "cred harvesting", "data staging", "process hollowing",
   "living-off-the-land". Avoid marketing language.
6. **Never embed secrets.** Guides must not include credentials, API keys,
   HEC tokens, or any other secret material (per the project's
   hardcoded-credentials rule).
7. **Prefer PEAK framing for the hard tier.** Hard-tier items should read
   like hypothesis-driven or baseline-driven hunt leads: hypothesis, data
   required, expected signal, and disproving criteria where useful.

## Quick compliance check

Before submitting a change that touches the campaign catalog, verify that
the campaign id set in `CAMPAIGN_META` equals the top-level key set of
`window.HuntGuides`. A simple check:

```bash
rg -o "\"[a-z]+\": \{" threatgen/api/campaigns.py | sort -u
rg -o "^  [a-z]+: \{" threatgen/static/js/hunt-guides.js | sort -u
```

The two lists must match. If they do not, the change is incomplete.
