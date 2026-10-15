#!/usr/bin/env bash
# Service smoke for an old-Git image (#1040): run the service, initialize a passphrase vault, and
# from inside a Git repository read ready status, start a task, change a file and run a
# deterministic check whose change capture must succeed.
#
# PR CI runs it inside condaforge/miniforge3:24.9.2-0 (Ubuntu 20.04, Git 2.25, glibc 2.31), the
# image whose every connection closed once the vault was ready (tb4n5). It never touches an
# everyday installation: every FinishUP process runs under a fresh FINISHUP_ISOLATED_ROOT, and the only
# service it stops is the one it started.
#
# Environment:
#   FINISHUP           launcher to exercise (default: finishup on PATH)
#   SMOKE_BASE         private 0700 directory for the isolated root, repository and logs
#                      (default: a new directory under $HOME; never /tmp, see ADR-026)
#   SMOKE_GIT          Git used to build the repository (default: the system Git FinishUP runs,
#                      the first git in /bin:/usr/bin)
#   EXPECT_GIT_SERIES  when set (e.g. 2.25), fail unless SMOKE_GIT reports that series, so the
#                      smoke cannot silently stop exercising an old Git
#   CEREMONY_PYTHON    Python for scripts/dogfood_ci/ceremony.py (default: python3)
#   CEREMONY           path to ceremony.py (default: next to this script's repository)
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
finishup=${FINISHUP:-finishup}
ceremony=${CEREMONY:-$here/../dogfood_ci/ceremony.py}
ceremony_python=${CEREMONY_PYTHON:-python3}
smoke_git=${SMOKE_GIT:-$(PATH=/bin:/usr/bin command -v git)}
base=${SMOKE_BASE:-$(mktemp -d "$HOME/.finishup-image-smoke.XXXXXX")}
mkdir -p "$base"
chmod 700 "$base"
out=$base/out
mkdir -p "$out"

git_version=$("$smoke_git" --version)
echo "system git: $git_version" | tee "$out/git-version.txt"
if [ -n "${EXPECT_GIT_SERIES:-}" ]; then
  case "$git_version" in
    "git version ${EXPECT_GIT_SERIES}."*) ;;
    *) echo "expected Git ${EXPECT_GIT_SERIES}.x, found: $git_version" >&2; exit 1 ;;
  esac
fi

export FINISHUP_ISOLATED_ROOT=$base/root
mkdir -p "$FINISHUP_ISOLATED_ROOT"
chmod 700 "$FINISHUP_ISOLATED_ROOT"

json_field() {
  # json_field FILE KEY: the first value named KEY anywhere in FILE's JSON document.
  "$ceremony_python" -I - "$1" "$2" <<'PY'
import json, sys

def find(value, key):
    if isinstance(value, dict):
        if key in value:
            return value[key]
        children = value.values()
    elif isinstance(value, list):
        children = value
    else:
        return None
    for child in children:
        found = find(child, key)
        if found is not None:
            return found
    return None

found = find(json.load(open(sys.argv[1], encoding="utf-8")), sys.argv[2])
if found is None:
    sys.exit(f"missing {sys.argv[2]} in {sys.argv[1]}")
print(json.dumps(found) if isinstance(found, (dict, list)) else found)
PY
}

"$finishup" service run 2>"$out/service.log" &
service=$!
stop_service() {
  (cd / && "$finishup" service stop --json >/dev/null 2>&1) || true
  wait "$service" 2>/dev/null || true
}
trap 'status=$?; stop_service; if [ $status -ne 0 ]; then cat "$out/service.log" >&2 || true; fi' EXIT

for _ in $(seq 1 120); do
  if (cd / && "$finishup" service status --json >"$out/status-locked.json" 2>/dev/null); then break; fi
  if ! kill -0 "$service" 2>/dev/null; then echo "service exited" >&2; exit 1; fi
  sleep 0.5
done
grep -q '"state":"locked"' "$out/status-locked.json"

# The trusted console needs a real terminal; ceremony.py gives it one and types the passphrase.
SMOKE_PASSPHRASE=$("$ceremony_python" -I -c 'import secrets; print(secrets.token_urlsafe(24))')
export SMOKE_PASSPHRASE
"$ceremony_python" -I "$ceremony" --secret-env SMOKE_PASSPHRASE \
  --reply 'Passphrase \(=@secret' --reply 'Confirm passphrase=@secret' \
  -- "$finishup" service initialize-passphrase --json 2>"$out/vault.txt"
grep -q '"state":"ready"' "$out/vault.txt"

repo=$base/repo
mkdir -p "$repo/src"
git_in_repo() {
  "$smoke_git" -C "$repo" -c user.name="FinishUP Smoke" -c user.email=smoke@finishup.invalid \
    -c commit.gpgsign=false "$@"
}
git_in_repo init -q
printf 'export const value = 1;\n' >"$repo/src/value.ts"
git_in_repo add src/value.ts
git_in_repo commit -q -m baseline

cd "$repo/src"
# Ready status from inside the repository: the handshake resolves its identity with this Git.
"$finishup" service status --json >"$out/status-ready.json"
grep -q '"state":"ready"' "$out/status-ready.json"

"$finishup" start --json --request "{
  \"protocol_version\": \"0.1\", \"schema_version\": \"1.0.0\",
  \"request_id\": \"req_$("$ceremony_python" -I -c 'import uuid; print(uuid.uuid4())')\",
  \"mode\": \"create_or_attach\", \"task_title\": \"Old-Git image smoke\",
  \"workspace_ref\": \"$repo\", \"external_ref\": \"image-smoke\",
  \"actor\": {\"actor_id\": \"harness:image-smoke\", \"actor_type\": \"harness\"},
  \"client\": {\"kind\": \"test_client\", \"version\": \"0.1.0\", \"integration\": \"local_cli\"},
  \"requested_view\": \"compact\"
}" >"$out/start.json"
session_id=$(json_field "$out/start.json" session_id)
writer_id=$(json_field "$out/start.json" writer_id)
frontier=$(json_field "$out/start.json" frontier)

printf 'export const value = 2;\n' >"$repo/src/value.ts"
printf 'export const added = true;\n' >"$repo/src/added.ts"
"$finishup" check --json --request "{
  \"protocol_version\": \"0.1\", \"schema_version\": \"1.0.0\",
  \"request_id\": \"req_$("$ceremony_python" -I -c 'import uuid; print(uuid.uuid4())')\",
  \"session_id\": \"$session_id\", \"writer_id\": \"$writer_id\",
  \"expected_frontier\": $frontier, \"mode\": \"deterministic_only\",
  \"actor\": {\"actor_id\": \"harness:image-smoke\", \"actor_type\": \"harness\"},
  \"client\": {\"kind\": \"test_client\", \"version\": \"0.1.0\", \"integration\": \"local_cli\"}
}" >"$out/check.json"
# The check-time change was captured: the test-edit baseline is known only when the structural
# capture read the repository, and a capture that could not reports
# check_time_change_unavailable_<reason> on the check instead.
if grep -Eq 'check_time_change_unavailable|preexisting_test_baseline_unknown' "$out/check.json" ||
  ! grep -q '"baseline_known":"1"' "$out/check.json"; then
  echo "check-time change capture failed:" >&2
  cat "$out/check.json" >&2
  exit 1
fi
echo "image smoke passed ($git_version)"
