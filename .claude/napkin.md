# Napkin Runbook

## Curation Rules
- Re-prioritize on every read.
- Keep recurring, high-value notes only.
- Max 10 items per category.
- Each item includes date + "Do instead".

## Execution & Validation (Highest Priority)
1. **[2026-04-23] Validate threat findings with multiple pivots**
   Do instead: corroborate each suspicious signal with at least one supporting query (host/user/time/source consistency) before calling it a confirmed threat.
2. **[2026-07-16] Editing threatgen/*.py restarts a running server (run.py uses reload=True) and kills active generation**
   Do instead: check `curl -s 127.0.0.1:8899/api/generator/status` before editing; if generation was running, restart it afterward via POST /api/generator/start.
3. **[2026-07-16] Real secrets live in the OS keychain (threatgen.anthropic / threatgen.splunk_hec)**
   Do instead: verify key endpoints with GET only (`/api/llm/key`); never PUT/DELETE round-trip during testing — it clobbers the user's stored key.

## Shell & Command Reliability
1. **[2026-04-23] Prefer MCP tools for Splunk operations**
   Do instead: use Splunk MCP query tools for searches and only use shell for local repository tasks.

## Domain Behavior Guardrails
1. **[2026-04-23] Use PEAK sequence for hunts**
   Do instead: run Prepare (data availability), Execute (baseline + anomaly), and Act (findings + confidence + next actions) in that order.

## User Directives
1. **[2026-04-23] Answer threat questions with concrete evidence**
   Do instead: return specific SPL-backed indicators, impacted entities, time windows, and confidence level instead of generic recommendations.
