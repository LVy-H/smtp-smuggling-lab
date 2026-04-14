# SMTP Smuggling Lab

A containerized reproduction of the SMTP smuggling vulnerability from:

> Wang et al., *Email Spoofing with SMTP Smuggling: How the Shared Email
> Infrastructures Magnify this Vulnerability*, USENIX Security '25
> (`usenixsecurity25-wang-chuhan.pdf`).

Built as a Network Security course project. The lab reproduces the
parser-differential on SMTP's end-of-data indicator (`<CR><LF>.<CR><LF>`)
between Postfix instances, captures wire traffic, and runs a Zeek-based
detection rule that flags the attack.

## Status

**M0 (Floor) — COMPLETE.** See `docs/status.md`.

- Lab: `postfix-sender` → `postfix-receiver` → `dovecot` (LMTP → Maildir)
  on isolated `labnet` Podman bridge, plus a `tcpdump` sidecar.
- Harness: raw-socket SMTP client (never `smtplib`).
- Oracle: RFC-strict stub SMTP server that replays captured pcaps.
- Detection: containerized Zeek script with two detectors
  (byte-pattern + transaction-rate).
- Result: paper's A1 (`\n.\n`) and A5 (`\r\n.\n`) both classify as
  **vulnerable** against Postfix 3.7 with `smtpd_forbid_bare_newline=no`.

## Requirements

- Linux host with Podman ≥ 5 and `podman-compose`.
- Python 3.11+.
- `docker.io/zeek/zeek:lts` image (pulled automatically by `reproduce.sh`).
- ~2 GB free RAM, ~4 GB disk for container images.

Kali rolling works out of the box. On distros with a stricter seccomp
profile you may not need `--security-opt seccomp=unconfined` in the
compose file; it's present here because this project was developed on
a host with a missing `seccomp.json`.

## Quickstart

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'

# Build lab images (one-time, ~2 minutes)
podman build --security-opt seccomp=unconfined -t smtp-lab-postfix:m0 lab/postfix/
podman build --security-opt seccomp=unconfined -t smtp-lab-dovecot:m0 lab/dovecot/
podman build --security-opt seccomp=unconfined -t smtp-lab-tcpdump:m0 lab/tcpdump-sidecar/
podman pull docker.io/zeek/zeek:lts

# Bring lab up
podman-compose -f lab/podman-compose.yml up -d

# Run M0 validation (connectivity smoke + A1/A5 cases + Zeek detection)
python -m harness.run_m0

# Teardown
podman-compose -f lab/podman-compose.yml down
```

Or run the whole pipeline end-to-end:

```bash
./reproduce.sh
```

## Test suite

```bash
. .venv/bin/activate
pytest tests/ -v
```

21 tests cover:
- Payload byte-preservation (base64 round-trips, line-ending integrity).
- Carrier template byte accuracy (CRLF discipline, NUL preservation).
- Stub SMTP receiver (RFC-strict DATA termination).
- Harness raw-socket SMTP client.
- Oracle pcap → stub replay pipeline.
- Zeek detection smoke (notice raised on vulnerable pcaps, silent on baseline).

## Directory layout

```
lab/            container images and podman-compose.yml
harness/        raw-socket SMTP client, payload loader, oracle, run_case, run_m0
detect/gateway/ Zeek script (smtp-smuggling.zeek)
payloads/       A1, A5 payloads as base64 YAML
results/        captured pcaps and stub event logs (committed as evidence)
tests/          pytest test suite + fixtures
docs/           specs, plans, status, primers
```

## Containment

All SMTP traffic stays on an isolated Podman bridge `labnet` in the
`10.89.2.0/24` subnet. The sender's port 25 is forwarded to
`127.0.0.1:2525` on the host for the harness to reach; no ports are
exposed on external interfaces. No payload ever reaches a real mail
server. See `docs/specs/2026-04-14-smtp-smuggling-lab-design.md` §10
for the full containment rules.

## Research findings so far

Running M0 reproduces the paper's finding against Postfix 3.7
(Debian 12) with `smtpd_forbid_bare_newline = no`:

| Payload | Family        | Bytes       | Classification |
|---------|---------------|-------------|----------------|
| A1      | bare-LF       | `\n.\n`     | vulnerable     |
| A5      | CRLF-dot-LF   | `\r\n.\n`   | vulnerable     |

For both cases, one harness send produces two emails delivered to
`bob@labnet.test` — the intended carrier plus the smuggled
`attacker@evil.test` message — and Zeek raises a
`Parser_Differential_Pattern` notice on the captured pcap.

## Next milestones

- **M1** — Full 13-payload × 4-MTA-pairing matrix (add Exim container,
  matrix renderer, golden-file regression, sender-side tcpdump capture).
- **M2** — Mutation fuzzer + patched-version probe (`debian:trixie-slim`
  with `smtpd_forbid_bare_newline = yes`).
- **M3** — Live bypass hunt against bounty-scoped real providers
  (default-off, guarded behind the `external/ENABLED` kill switch).
