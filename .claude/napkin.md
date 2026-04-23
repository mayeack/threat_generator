# Napkin Runbook

## Curation Rules
- Re-prioritize on every read.
- Keep recurring, high-value notes only.
- Max 10 items per category.
- Each item includes date + "Do instead".

## Execution & Validation (Highest Priority)
1. **[2026-04-23] Validate threat findings with multiple pivots**
   Do instead: corroborate each suspicious signal with at least one supporting query (host/user/time/source consistency) before calling it a confirmed threat.

## Shell & Command Reliability
1. **[2026-04-23] Prefer MCP tools for Splunk operations**
   Do instead: use Splunk MCP query tools for searches and only use shell for local repository tasks.

## Domain Behavior Guardrails
1. **[2026-04-23] Use PEAK sequence for hunts**
   Do instead: run Prepare (data availability), Execute (baseline + anomaly), and Act (findings + confidence + next actions) in that order.

## User Directives
1. **[2026-04-23] Answer threat questions with concrete evidence**
   Do instead: return specific SPL-backed indicators, impacted entities, time windows, and confidence level instead of generic recommendations.
