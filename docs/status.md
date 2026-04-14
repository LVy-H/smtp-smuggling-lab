# Project Status

**Spec:** `docs/specs/2026-04-14-smtp-smuggling-lab-design.md`
**Plan:** `docs/plans/2026-04-14-m0-smtp-smuggling-lab-floor.md`
**Current milestone:** M0 (Floor) — **COMPLETE** (tag `milestone-M0-complete`)

## M0 exit criteria (spec §2.M0)

- [x] `podman-compose up` brings the lab online in under 60 seconds
- [x] Connectivity smoke (EHLO/QUIT) against `127.0.0.1:2525` succeeds
- [x] Both A1 (`\n.\n`) and A5 (`\r\n.\n`) classify as vulnerable: Maildir shows 2 delivered emails for each
- [x] Zeek raises a `Parser_Differential_Pattern` notice for every vulnerable case pcap
- [x] This file (`docs/status.md`) describes current state

## Known deviations from spec

- **Zeek runs in a container** (`docker.io/zeek/zeek:lts`), not installed on the host. Reason: Kali rolling's `libc6 2.42-13` is incompatible with both Kali's `zeek 5.1.1-0kali3` (wants `libc6 < 2.38`) and the openSUSE Debian 12 build. The containerized path fits the lab architecture and avoids host libc issues.

- **tcpdump sidecar captures receiver-side traffic only.** The sidecar shares `postfix-receiver`'s network namespace. This means we see post-relay traffic, where a vulnerable sender has already laundered the smuggled bytes into two clean SMTP connections. The Zeek detector has a second "transaction-rate" rule specifically to catch this post-relay signal; the byte-pattern rule is reserved for a future capture position closer to the harness.

- **Dovecot is LMTP-only in M0.** IMAP is deferred to M1 where the live demo needs a mail client view. For M0, mailbox contents are inspected by `podman exec postfix-receiver ls /home/bob/Maildir/new/`.

- **M0 payload set is `{A1, A5}`**, not `{A1, A2, A5}` as the original plan text claimed. The plan's "A1 baseline row" (`\r\n.\r\n`) was conceptually broken: splicing the literal end-of-DATA sequence into a carrier always produces two emails. A1 was reassigned to the paper's canonical A1 (`\n.\n`) and the baseline sanity check was simplified to a plain EHLO/QUIT connectivity smoke in `run_m0.py` — no carrier is involved.

- **M0 oracle produces stub_event_count=1 for A1 in some runs.** This is because the A1 payload's bare-LF dot sequence gets *normalized away* by Postfix-sender as it re-emits two clean SMTP connections to postfix-receiver. The captured pcap (sender→receiver) no longer contains the A1 bytes — it contains two well-formed CRLF-only emails. So the stub replay sees only 1 complete transaction per connection. The Maildir file count (2) is the authoritative vulnerability indicator for this capture position. M1's plan will add a second tcpdump sidecar on the sender's ingress side so we can also capture the raw harness→sender bytes where A1 is still present.

## M0 evidence

- `results/pcaps/case-a1.pcap`, `case-a5.pcap` — live captures of the vulnerable cases
- `results/stub-events/case-a1.jsonl`, `case-a5.jsonl` — stub replay event logs
- `git tag milestone-M0-complete` — recoverable snapshot of this milestone

## Next

Write M1 plan (full 13 × 4 matrix, Exim container, matrix renderer, golden regression, sender-side tcpdump sidecar for raw-byte captures) after tagging `milestone-M0-complete`.
