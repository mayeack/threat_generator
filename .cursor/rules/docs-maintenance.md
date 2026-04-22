---
description: Keep all design documents (README.md, QUICKSTART.md, and any docs/*.md) synchronized with every code change in ThreatGen
globs: "**/*.py,**/*.yaml,**/*.yml,**/*.html,**/*.js,**/*.css,**/*.conf,requirements.txt,threatgen/**/*,splunk/**/*,scripts/**/*,skills/**/*"
alwaysApply: true
---

# Documentation Maintenance (ThreatGen)

Treat `README.md` and `QUICKSTART.md` as the canonical **design documents** for
this project. If a future `docs/` or design folder is added, every file under
it becomes part of this rule's scope automatically. Whenever you add, modify,
or remove a feature anywhere in the codebase, update the corresponding
documentation **in the same change/commit**. Documentation must always reflect
the current state of the application. A pull request that changes behavior but
does not update the docs is incomplete.

## Golden Rules

1. **Every feature change is a doc change.** Code + docs land together. Never
   defer doc updates to a follow-up.
2. **No stale counts or tables.** If a count, table row, or code tree entry
   describes something you just modified, update it in the same edit.
3. **Secrets stay in environment variables.** Any feature that accepts a
   credential (API key, HEC token, etc.) must be documented as env-var-only.
   Do **not** document or add persistence of secrets in `threatgen.db`,
   `default_config.yaml`, logs, or any API response.
4. **Install path is `/Applications/ThreatGenerator`.** Never `/Applications/ThreatGen`.
5. **Server URL is `http://127.0.0.1:8899`.** Use this everywhere in docs.
6. **Use the internal sourcetype keys consistently:** `wineventlog`, `sysmon`,
   `linux_secure`, `dns`, `http`, `firewall`.

## What triggers a documentation update

### Campaigns (`threatgen/engine/threats/`, `threatgen/api/campaigns.py`, `default_config.yaml`)
- Adding/removing a campaign: update the **Threat Campaigns** table in
  `README.md` (name, phases, sourcetypes, techniques, MITRE IDs) and the
  **Embedded Threat Campaigns** table in `QUICKSTART.md` (name, class,
  phases, sourcetypes). Update the campaign count (currently "Nine
  campaigns") wherever it appears in prose.
- Changing a campaign's phases, sourcetypes, techniques, IOC sources, or
  description: update the corresponding rows in both tables.
- Changing `CAMPAIGN_META` in `threatgen/api/campaigns.py`: mirror in the
  README campaign table.
- Adding/changing LLM-driven campaign planning (`threatgen/engine/threats/llm_plan.py`):
  update the **LLM** sections in `README.md` and `QUICKSTART.md` if the
  behavior (models, caching, fallback) changes.

### LLM subsystem (`threatgen/engine/llm/`, `threatgen/api/llm.py`, `threatgen/static/js/*` LLM UI)
- Adding/removing an LLM API route: update the **LLM (Claude-backed
  variation engine)** API table in `README.md`.
- Changing LLM config keys (in `default_config.yaml` under `llm:`): update
  the **LLM Settings** table in `README.md`.
- Changing models, pool sizing, refresh cadence, or fallback behavior:
  update the **Optional: Enable Claude-backed log variety** section and the
  **LLM pill** state table in `QUICKSTART.md`.
- The `ANTHROPIC_API_KEY` must be documented as environment-only in both
  docs. Never document persistence or API exposure of the key.
- Adding new worker states (e.g., `active`, `degraded`, `fallback`): update
  the pill-state table in `QUICKSTART.md`.

### HEC / Splunk forwarding (`threatgen/engine/hec/`, `threatgen/api/hec.py`, `threatgen/static/js/hec.js`)
- Adding/removing an HEC API route: update the **API Reference** in
  `README.md` with method, path, and description.
- Changing HEC config keys (`hec:` section in `default_config.yaml`):
  update the **Configuration Options** table in `README.md`.
- Changing HEC stats fields or runtime states: update any HEC status/pill
  documentation in `README.md` and `QUICKSTART.md`.
- The `SPLUNK_HEC_TOKEN` must be documented as environment-only. Do not
  document storing the token in the database, config file, or any API
  response (the API only returns a boolean `token_env_set`).
- If HEC becomes an alternative to file-based ingestion, update the
  **Ingest into Splunk** section in `QUICKSTART.md` to show both paths
  (UF + file monitors, and direct HEC).

### API endpoints (`threatgen/api/`)
- Adding/removing/changing a route: update the **API Reference** section in
  `README.md` (method, path, description). Group new routes under a
  descriptive subsection heading (e.g., `### HEC`, `### LLM`).
- Changing request/response models in `threatgen/models.py`: update the
  endpoint's description and any field tables.

### Web UI (`threatgen/static/`)
- Adding/removing a page or tab: update the **Web UI** table in `README.md`
  and the walkthrough steps in `QUICKSTART.md`.
- Adding/changing controls on an existing page: update that page's
  description in the Web UI table (e.g., new sliders, toggles, buttons,
  pills, status badges).
- Adding a new status pill (LLM, HEC, etc.): document its states in both
  the README Web UI table and the QUICKSTART pill-state tables.

### Architecture (`threatgen/`, top-level dirs)
- Adding/removing files or directories under `threatgen/`: update the
  **Architecture** tree in `README.md` and add a one-line comment for each
  new file describing its purpose.
- Adding new top-level directories (e.g., `scripts/`, `splunk/`,
  `skills/`): add them to the tree with a brief description.
- Adding a new engine subsystem (e.g., `engine/llm/`, `engine/hec/`):
  document each module under its own subtree in the Architecture section.

### Sourcetypes (`threatgen/engine/generators/`, `threatgen/engine/formatters/`)
- Adding/removing a sourcetype generator: update the **Sourcetypes** table
  in `README.md`, the **Log Output Files** table in `QUICKSTART.md`, the
  WebSocket paths list, and the `inputs.conf` example in `QUICKSTART.md`.
- If Splunk sourcetype names or file names change, update **all** places
  they appear (TA notes, troubleshooting table, ingestion steps).

### Configuration (`threatgen/default_config.yaml`, `threatgen/engine/config.py`)
- Adding/changing configuration options (any top-level key such as
  `diurnal`, `llm`, `hec`, `sourcetype_weights`, `campaigns`): update the
  **Configuration Options** table in `README.md`. For subsystems with many
  knobs (LLM, HEC), add a dedicated subtable.
- Changing defaults: update the default value in the docs.

### Dependencies (`requirements.txt`)
- Adding/removing/pinning a dependency: update the **Dependencies** table
  in `README.md` and the **Python Dependencies** table in `QUICKSTART.md`
  (including min version and purpose).

### Database (`threatgen/database.py`)
- Adding/changing tables or schema: update the Architecture section's
  database description in `README.md`.
- Adding new persisted state: confirm it is **not** a secret. If it is,
  move it to environment-only and do not document persistence.

### Splunk TAs and ingestion (`splunk/`)
- Changing TA structure or adding new TAs: update the Architecture tree in
  `README.md` and the Splunk deployment steps + troubleshooting table in
  `QUICKSTART.md`.
- Adding HEC as an ingestion path alongside UF: add a parallel section in
  `QUICKSTART.md` step 7 that covers HEC setup (token env var, URL,
  `SPLUNK_HEC_TOKEN`, TLS verification).

### Skills (`skills/`)
- Adding/removing a skill directory: update the **Architecture** tree in
  `README.md`.

### Scripts (`scripts/`)
- Adding user-facing utility scripts: document them in `QUICKSTART.md`
  under a "Common Tasks" or "Utilities" subsection.

## Catch-all

If you are introducing a capability that does not fit any bucket above
(new subsystem, new transport, new UI affordance, new persistence layer,
new background worker, new optional integration), you **must** still:

1. Add it to the **Architecture** tree in `README.md`.
2. Add/extend an API Reference subsection if it exposes HTTP routes.
3. Add/extend a Configuration Options row if it reads from
   `default_config.yaml`.
4. Add a user-visible walkthrough step or "Optional" callout in
   `QUICKSTART.md` if it changes what the user sees or how they run the
   app.
5. If it consumes a secret, document the env-var name and reaffirm that
   the secret is never persisted.

## Editorial rules

- Keep tables factual and concise. Do not add speculative or aspirational
  features.
- Prefer updating an existing table row over appending a new paragraph.
- When a feature is optional, say so explicitly and describe the fallback
  behavior.
- When a feature requires an environment variable, show the exact variable
  name in a fenced example and state where it is read and that it is not
  persisted.
- Cross-link: when `QUICKSTART.md` references a concept in depth, link to
  the relevant `README.md` section.
