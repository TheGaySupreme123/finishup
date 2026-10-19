#!/usr/bin/env bash
# Shared GitHub Actions test isolation. Never select an installed FinishUP instance.
set -euo pipefail

: "${RUNNER_TEMP:?GitHub Actions runner temp directory is required}"
: "${GITHUB_ENV:?GitHub Actions environment file is required}"

test_home="${RUNNER_TEMP}/h"
pytest_root="${RUNNER_TEMP}/pt"
install -d -m 0700 "$test_home" "$pytest_root" \
  "$test_home/.local/share" "$test_home/.config" "$test_home/.cache"
{
  echo "HOME=$test_home"
  echo "XDG_DATA_HOME=$test_home/.local/share"
  echo "XDG_CONFIG_HOME=$test_home/.config"
  echo "XDG_CACHE_HOME=$test_home/.cache"
  echo "PYTEST_ADDOPTS=--basetemp=$pytest_root"
  echo "YZCI_DENY_NETWORK=1"
} >> "$GITHUB_ENV"
