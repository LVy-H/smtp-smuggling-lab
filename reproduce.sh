#!/usr/bin/env bash
# End-to-end reproduction from a clean clone. Runs M0 (floor) and then
# the full M1 matrix. Exits non-zero on any failure. Idempotent.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"

echo "=== reproduce.sh: step 1/6 — check prerequisites ==="
command -v podman >/dev/null || { echo "podman not found"; exit 2; }
command -v podman-compose >/dev/null || { echo "podman-compose not found"; exit 2; }
command -v python3 >/dev/null || { echo "python3 not found"; exit 2; }

echo "=== reproduce.sh: step 2/6 — build lab images ==="
podman build --security-opt seccomp=unconfined -t smtp-lab-postfix:m0 lab/postfix/ >/dev/null
podman build --security-opt seccomp=unconfined -t smtp-lab-exim:m1     lab/exim/ >/dev/null
podman build --security-opt seccomp=unconfined -t smtp-lab-dovecot:m0 lab/dovecot/ >/dev/null
podman build --security-opt seccomp=unconfined -t smtp-lab-tcpdump:m0 lab/tcpdump-sidecar/ >/dev/null
podman pull docker.io/zeek/zeek:lts >/dev/null

echo "=== reproduce.sh: step 3/6 — Python venv + deps ==="
if [ ! -d .venv ]; then
    python3 -m venv .venv
fi
. .venv/bin/activate
pip install -q -e '.[dev]'

echo "=== reproduce.sh: step 4/6 — M0 floor (p2p profile) ==="
podman-compose -f lab/podman-compose.yml --profile p2p down >/dev/null 2>&1 || true
TARGET_RECEIVER=postfix-receiver podman-compose -f lab/podman-compose.yml --profile p2p up -d >/dev/null
sleep 6
python -m harness.run_m0
podman-compose -f lab/podman-compose.yml --profile p2p down >/dev/null 2>&1 || true

echo "=== reproduce.sh: step 5/6 — M1 full matrix ==="
python -m harness.run_matrix
python -m harness.render_matrix

echo "=== reproduce.sh: step 6/6 — Zeek coverage report ==="
python -m harness.verify_zeek_coverage

echo
echo "Done. See:"
echo "  results/matrix.md          (pairing × payload table)"
echo "  results/zeek-coverage.json (Zeek per-case coverage report)"
echo "  docs/status.md             (project status)"
