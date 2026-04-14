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

**M1 (Paper match) — COMPLETE.** See `docs/status.md`.

- Lab: 4 pairing profiles (`p2p`, `p2e`, `e2p`, `e2e`) over Postfix 3.7
  and Exim 4.96, each with a sender-side and receiver-side tcpdump sidecar.
- Harness: raw-socket SMTP client (never `smtplib`), 13-payload corpus.
- Oracle: RFC-strict stub SMTP server, replayed against both pcap positions.
- Detection (inline): containerized Zeek script with byte-pattern +
  transaction-rate rules. **14 / 14 vulnerable cells caught (100 % recall).**
- Detection (offline): Postfix mail.log / Exim mainlog parser.
- Result: 14 / 52 cells vulnerable, all in the two Postfix-sender columns.
  Exim sender is structurally immune because its outbound transport uses
  `BDAT`/`CHUNKING` instead of dot-terminated `DATA`. See
  `results/matrix.md` for the full pairing × payload table.

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

# Build lab images (one-time, ~3 minutes)
podman build --security-opt seccomp=unconfined -t smtp-lab-postfix:m0 lab/postfix/
podman build --security-opt seccomp=unconfined -t smtp-lab-exim:m1     lab/exim/
podman build --security-opt seccomp=unconfined -t smtp-lab-dovecot:m0 lab/dovecot/
podman build --security-opt seccomp=unconfined -t smtp-lab-tcpdump:m0 lab/tcpdump-sidecar/
podman pull docker.io/zeek/zeek:lts

# M0: floor validation (connectivity smoke + A1/A5 cases + Zeek detection).
podman-compose -f lab/podman-compose.yml --profile p2p up -d
python -m harness.run_m0
podman-compose -f lab/podman-compose.yml --profile p2p down

# M1: full 13-payload × 4-pairing matrix + Zeek coverage report.
python -m harness.run_matrix              # writes results/matrix.json
python -m harness.render_matrix           # writes results/matrix.md
python -m harness.verify_zeek_coverage    # writes results/zeek-coverage.json
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

Test suites:
- `tests/test_payloads.py` — all 13 paper payloads round-trip byte-for-byte
- `tests/test_carrier.py` / harness internals — CRLF discipline, NUL preservation
- `tests/test_log_parser.py` — Postfix mail.log + Exim mainlog parsers
- `tests/test_matrix.py` — golden regression on the 52-cell matrix
- M0 byte-preservation, stub, send, oracle and Zeek smoke tests

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

## Research findings (M1)

13 payloads × 4 MTA pairings = 52 cells. **14 / 52 cells are vulnerable**, all
in the two Postfix-sender columns:

| Payload | P → P | P → E | E → P | E → E |
|---------|:-----:|:-----:|:-----:|:-----:|
| A1 `\n.\n`              | ✗ | ✗ | ✓ | ✓ |
| A2 `\n.\r\n`            | ✗ | ✗ | ✓ | ✓ |
| A3 `\r.\r`              | ✓ | ✓ | ✓ | ✓ |
| A4 `\r.\r\n`            | ✓ | ✓ | ✓ | ✓ |
| A5 `\r\n.\n`            | ✗ | ✗ | ✓ | ✓ |
| A6 `\r\n.\r`            | ✓ | ✓ | ✓ | ✓ |
| A7 `\x00\r\n.\r\n`      | ✗ | ✗ | ✓ | ✓ |
| A8 `\r\n\x00.\r\n`      | ✓ | ✓ | ✓ | ✓ |
| A9 `\r\x00\n.\r\n`      | ✗ | ✗ | ✓ | ✓ |
| A10 `\x00\r\n.\r\n`     | ✗ | ✗ | ✓ | ✓ |
| A11 `\r\n.\x00\r\n`     | ✓ | ✓ | ✓ | ✓ |
| A12 `\r\n.\r\x00\n`     | ✓ | ✓ | ✓ | ✓ |
| A13 `\r\n.\r\n\x00`     | ✗ | ✗ | ✓ | ✓ |

Two key observations:
1. The receiver MTA does **not** change the outcome — Postfix 3.7's bare-LF
   tolerance on the *sender* side determines smuggling success.
2. Exim 4.96 sender is structurally immune because its `remote_smtp` transport
   negotiates `CHUNKING` and frames the body with `BDAT 935 LAST` instead of
   dot-terminated `DATA`. Length-prefix framing makes dot-based smuggling
   syntactically impossible. This is exactly the hardening the paper recommends.

The Zeek inline detector catches all 14 vulnerable cells (100 % recall) with
2 false positives on A8 (`\x00.\r\n`); see `results/zeek-coverage.json`.

## Next milestones

- **M2** — Live demo via Dovecot IMAP: send one vulnerable cell against the
  live lab and pull both the carrier and the smuggled message back through
  an IMAP client.
- **M3** — Live bypass hunt against bounty-scoped real providers
  (default-off, guarded behind the `external/ENABLED` kill switch).
