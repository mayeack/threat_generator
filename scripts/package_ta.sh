#!/usr/bin/env bash
# Build a Splunk Cloud-uploadable tarball of TA-threat_gen.
#
# Produces dist/TA-threat_gen-<version>.tgz from splunk/TA-threat_gen/, with the
# exclusions required by AppInspect cloud tags (no local/, no local.meta, no
# VCS/OS junk).
#
# Usage:
#   ./scripts/package_ta.sh
set -euo pipefail

APP=TA-threat_gen
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_ROOT="${REPO_ROOT}/splunk/${APP}"
APP_CONF="${APP_ROOT}/default/app.conf"

if [[ ! -f "${APP_CONF}" ]]; then
  echo "error: ${APP_CONF} not found" >&2
  exit 1
fi

VERSION="$(awk -F'= *' '/^version[[:space:]]*=/ {print $2; exit}' "${APP_CONF}")"
if [[ -z "${VERSION}" ]]; then
  echo "error: could not parse version from ${APP_CONF}" >&2
  exit 1
fi

DIST_DIR="${REPO_ROOT}/dist"
OUT="${DIST_DIR}/${APP}-${VERSION}.tgz"
mkdir -p "${DIST_DIR}"

# Skip macOS AppleDouble emission even if xattrs reappear (tar on macOS
# otherwise writes ._filename sidecars that Splunk AppInspect Cloud rejects).
export COPYFILE_DISABLE=1

# Scrub extended attributes from the source tree so tar has nothing to sidecar.
xattr -rc "${APP_ROOT}" 2>/dev/null || true

tar -czvf "${OUT}" \
  -C "${REPO_ROOT}/splunk" \
  --exclude='local' \
  --exclude='local/*' \
  --exclude='metadata/local.meta' \
  --exclude='.DS_Store' \
  --exclude='._*' \
  --exclude='.AppleDouble' \
  --exclude='__MACOSX' \
  --exclude='*.pyc' \
  --exclude='__pycache__' \
  --exclude='.git' \
  "${APP}"

echo
echo "Built ${OUT}"
