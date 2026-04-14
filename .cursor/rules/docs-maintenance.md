---
description: Keep README.md and QUICKSTART.md synchronized with code changes
globs: "**/*.py,**/*.yaml,**/*.yml,**/*.html,**/*.js,**/*.css,**/*.conf,requirements.txt"
---

# Documentation Maintenance

When you add, modify, or remove features in the ThreatGen codebase, update the corresponding documentation in `README.md` and `QUICKSTART.md` as part of the same change. Documentation must always reflect the current state of the application.

## What triggers a documentation update

### Campaigns (`threatgen/engine/threats/`, `threatgen/api/campaigns.py`, `default_config.yaml`)
- Adding or removing a campaign: update the **Threat Campaigns** table in `README.md` (all columns: name, phases, sourcetypes, techniques, MITRE IDs) and the **Embedded Threat Campaigns** table in `QUICKSTART.md` (name, class, phases, sourcetypes). Update the campaign count in prose wherever it appears.
- Changing a campaign's phases, sourcetypes, MITRE techniques, or description: update the corresponding row in both tables.
- Changing `CAMPAIGN_META` in `threatgen/api/campaigns.py`: ensure the README campaign table matches.

### API endpoints (`threatgen/api/`)
- Adding, removing, or changing a route: update the **API Reference** section in `README.md` (method, path, description).
- Changing request/response models: update the endpoint description.

### Web UI (`threatgen/static/`)
- Adding or removing a page/tab: update the **Web UI** table in `README.md`.
- Adding or changing controls on an existing page: update that page's description in the Web UI table.

### Architecture (`threatgen/`)
- Adding or removing files or directories: update the **Architecture** tree in `README.md`.
- Adding new top-level directories (e.g., `scripts/`, `splunk/`, `skills/`): add them to the tree.

### Sourcetypes (`threatgen/engine/generators/`, `threatgen/engine/formatters/`)
- Adding or removing a sourcetype generator: update the **Sourcetypes** table in `README.md` and the **Log Output Files** table in `QUICKSTART.md`.
- Update the WebSocket section if valid sourcetype names change.

### Configuration (`threatgen/default_config.yaml`, `threatgen/engine/config.py`)
- Adding or changing configuration options: update the **Configuration Options** table in `README.md`.

### Dependencies (`requirements.txt`)
- Adding or removing a dependency: update the **Dependencies** table in `README.md` and the **Python Dependencies** table in `QUICKSTART.md`.

### Database (`threatgen/database.py`)
- Adding or changing tables/schema: update the Architecture section's database description in `README.md`.

### Splunk TAs (`splunk/`)
- Changing TA structure or adding new TAs: update the Architecture tree in `README.md` and the Splunk deployment steps in `QUICKSTART.md`.

## Rules

- Keep tables factual and concise. Do not add speculative or aspirational features.
- Use the same internal sourcetype keys consistently: `wineventlog`, `sysmon`, `linux_secure`, `dns`, `http`, `firewall`.
- The install path is `/Applications/ThreatGenerator`. Never use `/Applications/ThreatGen`.
- The server runs on `http://127.0.0.1:8899`.
