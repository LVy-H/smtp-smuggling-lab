# Project Status

**Spec:** `docs/specs/2026-04-14-smtp-smuggling-lab-design.md`
**Plan:** `docs/plans/2026-04-14-m0-smtp-smuggling-lab-floor.md`
**Current milestone:** M1 (Paper match) — **COMPLETE** (tag `milestone-M1-complete`)

## M1 exit criteria (spec §2.M1)

- [x] Exim 4.96 container builds and serves SMTP on labnet (sender + receiver roles)
- [x] All 13 paper payloads (A1–A13) defined in `payloads/payloads.yaml`, byte-preserving tests pass
- [x] Compose ships 4 pairing profiles (`p2p`, `p2e`, `e2p`, `e2e`), each with sender + receiver + dual tcpdump sidecars
- [x] `harness/run_matrix.py` brings each profile up in turn and runs all 13 payloads → 52 cells in `results/matrix.json`
- [x] `harness/render_matrix.py` produces `results/matrix.md` for the report
- [x] Golden regression test `tests/test_matrix.py` populated and passing (52 cells locked in `tests/expected_matrix.json`)
- [x] Offline log-parser detector `detect/logs/parse_mail_log.py` runs against per-case mail.log / mainlog dumps
- [x] Inline Zeek detector catches **14 / 14** vulnerable cells (100 % recall) on sender-side pcaps
- [x] Full 11-test suite (`tests/test_payloads.py`, `tests/test_log_parser.py`, `tests/test_matrix.py`) passes

## M1 matrix headline (`results/matrix.md`)

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

Legend: ✗ vulnerable, ✓ not-vulnerable. **14 / 52 cells = vulnerable.**

### Findings

1. **The sender MTA decides smuggling success in this lab.** All 14 vulnerable cells live in the
   two Postfix-sender columns. Postfix 3.7 (Debian 12) preserves the bare-LF / NUL-byte dot
   sequences when forwarding, so a vulnerable receiver sees the smuggled mail intact. The
   choice of receiver MTA (Postfix vs Exim) does not change the outcome on these 13 payloads:
   any payload that succeeds against P → P also succeeds against P → E.
2. **Exim 4.96 sender is structurally immune to dot-terminator smuggling** because its
   `remote_smtp` transport advertises and uses `CHUNKING` (`BDAT 935 LAST` instead of `DATA`).
   With a length-prefixed body the dot sequence loses its meaning entirely; the receiver
   parses the BDAT chunk as opaque bytes regardless of what the bytes say. This matches the
   paper's recommendation to deploy CHUNKING as a hardening measure.
3. **The 7 “Postfix-vulnerable” payloads** (A1, A2, A5, A7, A9, A10, A13) all share a
   `<LF>.<LF>` or `<NUL><CRLF>.<CRLF>` shape that Postfix's parser still treats as a body
   terminator, while the harness's strict-RFC stub keeps reading. The 6 “Postfix-immune”
   payloads (A3, A4, A6, A8, A11, A12) all hinge on a bare `\r` or an inserted NUL inside the
   `.<CRLF>` sequence — Postfix's dot-stuffing pre-processor strips or normalizes those.

## Detection scoreboard

| Detector            | Recall on vulnerable | False positives | Notes |
|---------------------|----------------------|-----------------|-------|
| Zeek inline (gateway) | **14 / 14 (100 %)** | 2 / 38 (A8 only) | Byte-pattern detector flags A8's `\x00.\r\n` even when the receiver happens to strip the NUL. Acceptable precision for an inline tap. |
| Postfix log-parser  | 14 / 14 visible as `multi-queue-per-client` notices | High: queue-id dedup is the only signal | Logs only see the post-normalize side, so smuggling proves itself only via the *count* of queue IDs from one client IP. |
| Exim mainlog parser | 0 / 0 vulnerable to detect | High: fires whenever the same IP submits ≥2 mails | Exim never produces a vulnerable cell so the parser has no positives to match. The parser still demonstrates the expected "many mails from one client" pattern but precision is poor on its own. |

## Known deviations from spec

- **Zeek runs in a container** (`docker.io/zeek/zeek:lts`), not installed on the host.
  Reason: Kali rolling's `libc6 2.42-13` is incompatible with both Kali's `zeek 5.1.1-0kali3`
  (wants `libc6 < 2.38`) and the openSUSE Debian 12 build. The containerized path fits the
  lab architecture and avoids host libc issues.
- **Sender-side stub event count is 0 for every Exim-sender cell.** This is not a regression:
  the captured pcap shows `BDAT 935 LAST` rather than `DATA … \r\n.\r\n`, so the
  RFC-strict stub never fires `data_complete`. Vulnerability for these cells is decided by
  the receiver Maildir count alone, which is the right ground truth.
- **Log-parser coverage is intentionally noisy.** The Exim mainlog inside an Exim sender
  container accumulates across the whole 13-payload run, so the per-case dump sees a growing
  count of `<=` lines. We do not reset the log between cases — the cumulative count is the
  signal.
- **A8 produces 2 false positives in Zeek.** Both lab receivers strip the NUL byte and drop
  the smuggled half, so A8 is "not-vulnerable" in the matrix even though Zeek correctly
  identifies the wire bytes as suspicious. The conservative inline notice is the right
  trade-off.

## M0 evidence (preserved)

- `git tag milestone-M0-complete` — recoverable snapshot of the floor milestone

## M1 evidence

- `results/matrix.json`, `results/matrix.md` — full 52-cell pairing × payload matrix
- `results/pcaps/case-<pair>-<payload>-{sender,receiver}.pcap` — both wire positions per case
- `results/stub-events/case-<pair>-<payload>-{sender,receiver}.jsonl` — strict-RFC stub events
- `results/logs/case-<pair>-<payload>/{mail.log,mainlog}` — per-case sender mail-log dumps
- `results/log-parser-notices.json` — log-parser notices per case
- `results/zeek-coverage.json` — Zeek per-case notices, with summary of misses and false positives
- `tests/expected_matrix.json` — golden regression for the matrix
- `git tag milestone-M1-complete` — recoverable snapshot of this milestone

## Next

Continue into M2 (live demo): bring up Dovecot IMAP, write a one-shot demo script that
sends one of the vulnerable cells against the live lab and pulls both the carrier and the
smuggled message back over IMAP. M3 (external corpus replay) remains gated behind the
`external/ENABLED` kill-switch file.
