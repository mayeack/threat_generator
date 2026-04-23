#!/usr/bin/env bash
# Run Splunk AppInspect against a packaged TA-threat_gen tarball using the
# cloud tag set. Requires the splunk-appinspect CLI:
#
#   pip install splunk-appinspect
#
# Usage:
#   ./scripts/validate_ta.sh                           # validates newest dist/TA-threat_gen-*.tgz
#   ./scripts/validate_ta.sh path/to/TA-threat_gen.tgz
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v splunk-appinspect >/dev/null 2>&1; then
  echo "error: splunk-appinspect not found on PATH" >&2
  echo "install with: pip install splunk-appinspect" >&2
  exit 1
fi

if [[ $# -ge 1 ]]; then
  PKG="$1"
else
  PKG="$(ls -t "${REPO_ROOT}/dist"/TA-threat_gen-*.tgz 2>/dev/null | head -n 1 || true)"
fi

if [[ -z "${PKG:-}" || ! -f "${PKG}" ]]; then
  echo "error: no package to validate. Run ./scripts/package_ta.sh first or pass a tarball path." >&2
  exit 1
fi

echo "Validating ${PKG} with cloud tags..."
splunk-appinspect inspect "${PKG}" --mode precert --included-tags cloud
