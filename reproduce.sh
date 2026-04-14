#!/usr/bin/env bash
# End-to-end M0 reproduction from a clean clone. Exits non-zero on any
# failure. Idempotent: safe to run repeatedly.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"

echo "=== reproduce.sh: step 1/5 — check prerequisites ==="
command -v podman >/dev/null || { echo "podman not found"; exit 2; }
command -v podman-compose >/dev/null || { echo "podman-compose not found"; exit 2; }
command -v python3 >/dev/null || { echo "python3 not found"; exit 2; }

echo "=== reproduce.sh: step 2/5 — build lab images ==="
podman build --security-opt seccomp=unconfined -t smtp-lab-postfix:m0 lab/postfix/ >/dev/null
podman build --security-opt seccomp=unconfined -t smtp-lab-dovecot:m0 lab/dovecot/ >/dev/null
podman build --security-opt seccomp=unconfined -t smtp-lab-tcpdump:m0 lab/tcpdump-sidecar/ >/dev/null
podman pull docker.io/zeek/zeek:lts >/dev/null

echo "=== reproduce.sh: step 3/5 — Python venv + deps ==="
if [ ! -d .venv ]; then
    python3 -m venv .venv
fi
. .venv/bin/activate
pip install -q -e '.[dev]'

echo "=== reproduce.sh: step 4/5 — bring up lab ==="
podman-compose -f lab/podman-compose.yml down >/dev/null 2>&1 || true
podman-compose -f lab/podman-compose.yml up -d >/dev/null
trap 'podman-compose -f lab/podman-compose.yml down >/dev/null 2>&1 || true' EXIT
sleep 6

echo "=== reproduce.sh: step 5/5 — run M0 ==="
python -m harness.run_m0
