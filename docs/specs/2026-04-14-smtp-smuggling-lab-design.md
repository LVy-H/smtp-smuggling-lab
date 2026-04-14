# SMTP Smuggling Lab & Detection — Design Spec

**Date:** 2026-04-14
**Source paper:** Wang et al., *"Email Spoofing with SMTP Smuggling: How the Shared Email Infrastructures Magnify this Vulnerability"*, USENIX Security '25 (`usenixsecurity25-wang-chuhan.pdf`)
**Project type:** Network Security course deliverable — report + live demo
**Target duration:** 2–3 weeks, tiered so that an always-submittable artifact exists from the end of week 1 onward

---

## 1. Goal and Non-Goals

### Goal

Build a containerized lab that reproduces the 13 SMTP smuggling payload variants (A₁–A₁₃) catalogued in Table 1 of the paper against both Postfix and Exim, and build two detectors — a primary Zeek-based inline sensor and a secondary log parser — that flag the attack. Deliver a written report and a live demo; design every component so that partial completion is still submittable.

### Non-Goals

- Reproducing the paper's *public-service* measurements against real email providers (qq.com, Sina, Gmail, etc.). This project is a local lab; no traffic leaves `labnet`.
- Building a hardened / production-grade detector. The Zeek rule is for coursework and does not need to handle adversarial evasion beyond the paper's and our own fuzzer's variants.
- DKIM/SPF/DMARC *infrastructure* reproduction. Authentication is out of scope except insofar as A₁ (baseline `\r\n.\r\n`) must successfully deliver a normal email.

---

## 2. Tiered Milestones

The project is structured as three nested tiers. Each tier has a **hard exit criterion**: if hit, the project is submittable at that tier's level. A `git tag milestone-M<N>-complete` is created at each exit to make the floor explicit and recoverable.

### M0 — Floor ("something to submit, even in the worst case") — target: end of day 3

**Scope:** End-to-end toolchain proven on 3 payloads against 1 MTA pairing (Postfix → Postfix).

**Exit criteria (all required):**

1. `podman-compose up` brings the lab online (`postfix-sender`, `postfix-receiver`, `dovecot`, `zeek`, harness) in under 60 seconds.
2. Harness sends A₁ (baseline `\r\n.\r\n`) → stub receiver reports **exactly 1** email. Harness sanity check.
3. Harness sends A₂ (`\n.\n`) and A₅ (`\r\n.\n`) → for at least **one** payload, stub reports **≥2** events *and* Dovecot mailbox shows a second email.
4. Zeek processes the same case pcap and raises a notice for the vulnerable case.
5. `docs/status.md` exists describing current state, known gaps, next steps.

### M1 — Paper Match — target: end of week 2

**Scope:** Full 13 payloads × 4 MTA pairings (P→P, P→E, E→P, E→E) = 52 cells.

**Exit criteria:**

1. Every cell in the matrix has a recorded outcome from the set `{vulnerable, sanitized-by-sender, rejected-by-receiver, silently-dropped}` — no `TODO` / `unknown` cells.
2. `python harness/run_matrix.py` generates `results/matrix.json` and `results/matrix.md` from actual observed test runs; the report's matrix table is rendered from the same JSON.
3. Zeek rule detects every `vulnerable` cell with no false positives on non-vulnerable cells. False positives, if any, are documented as findings, not hidden.
4. Log parser is run on every case; its coverage column is populated. Zeek-vs-log-parser coverage gap is quantified in one sentence in the report.
5. `./reproduce.sh` on a clean machine produces the full matrix in under 15 minutes.

### M2 — Beyond the Paper — target: end of week 3, only if M1 green

**Scope:** Exploratory / open-ended; exit criterion is "you tried and wrote up what happened," not "you found a CVE."

**Concrete approaches, in order of expected payoff:**

1. **Mutation fuzzer** (~150 lines Python). Seeds: A₁–A₁₃. Mutations: C0 control-byte swaps for `\x00`, dot count variation, UTF-8 overlong encoding of `.` (`\xc0\xae`), multi-byte sequences around the dot. Any candidate producing stub N>1 is added to `payloads.yaml` with `family: m2-discovered`.
2. **Patched-version probe.** Rebuild lab with `debian:trixie-slim` (Postfix 3.9, Exim 4.98 — both patched). Rerun full matrix plus M2 fuzzer output. A bypass is a finding; zero bypasses is also a reportable result.
3. **Sender-side stability analysis.** From M1 pcaps, identify payloads where the sender did not sanitize; fuzz those specifically for sender-stable variants.

**Exit criterion:** At least one of the three yields a written finding in `results/m2-findings.md` (positive or negative).

---

## 3. Architecture

### 3.1 Container topology

Seven containers on one isolated Podman bridge `labnet`. Nothing is forwarded to the host except Dovecot IMAP on `127.0.0.1:1143` for the demo only. Every container runs with `--security-opt seccomp=unconfined` (user's local `seccomp.json` is broken and this removes a class of runtime errors upfront).

```
 ┌─────────────┐    SMTP     ┌──────────────┐    SMTP     ┌────────────────┐    LMTP    ┌──────────┐
 │  harness    │────────────►│ sending-mta  │────────────►│ receiving-mta  │───────────►│ dovecot  │
 │ (python +   │   port 25   │ (postfix OR  │   port 25   │  (postfix OR   │            │ (demo    │
 │  pytest)    │             │    exim)     │             │    exim)       │            │ oracle)  │
 └─────────────┘             └──────────────┘             └────────────────┘            └──────────┘
        │                            │                            │
        │                    (shared pcap volume)         (shared pcap volume)
        │                            │                            │
        │                            └──────────┬─────────────────┘
        │                                       ▼
        │                          ┌──────────────────────┐   ┌──────────────────┐
        │                          │ zeek (primary        │   │ logparser        │
        └─────────────────────────►│ detector: AF_PACKET  │   │ (contrast: tail  │
                                   │ on labnet bridge)    │   │ mail.log)        │
                                   └──────────────────────┘   └──────────────────┘
```

### 3.2 MTA images and version pinning

Two images are built, both from `debian:12-slim`:

- `lab/postfix/` — Debian 12 ships Postfix 3.7, which is **vulnerable by default**. `smtpd_forbid_bare_newline` must be explicitly set to `no` in `main.cf` for reproducibility under future Debian updates.
- `lab/exim/` — Debian 12 ships Exim 4.96, which is vulnerable to several A₁–A₁₃ variants.

For M2's patched-version probe, a second set of images is built from `debian:trixie-slim` (Postfix 3.9, Exim 4.98 — both patched).

Each MTA image runs twice in the compose file — once as `*-sender`, once as `*-receiver` — with different config mounts. The four pairings (P→P, P→E, E→P, E→E) are selected via **Podman Compose profiles**, not all four running simultaneously, so the harness always knows exactly which pair produced a given pcap.

### 3.3 Resource footprint

Target steady state: **≤2 GB RAM** for the full lab (4 MTA containers are never live at once; at most 2 MTA containers + Dovecot + Zeek + harness). The user has ≥8 GB available and 100 GB disk, so neither is a constraint.

---

## 4. Payload Model

All 13 paper payloads plus any M2-discovered variants live in **one file**, `payloads/payloads.yaml`, which is the single source of truth for the harness, the result matrix generator, and the report tables.

### 4.1 Byte-preservation discipline

Every payload field is stored **base64-encoded**. Git, YAML parsers, text editors, and log shippers all silently normalize line endings; base64 makes line-ending mutation impossible in transit. The harness decodes exactly once, at the moment of `socket.sendall`.

### 4.2 Schema

```yaml
- id: A1
  bytes_b64: "DQouDQo="              # "\r\n.\r\n" — legitimate terminator, sanity row
  family: baseline
  paper_ref: "Table 1, Appendix A"
  expected_stub_events: 1            # baseline MUST deliver exactly one email

- id: A2
  bytes_b64: "Ci4K"                   # "\n.\n"
  family: bare-lf
  paper_ref: "Table 1, §3.1"
  smuggled_sender: "attacker@evil.test"
  smuggled_subject: "SMUGGLED-A2"
  # expected_stub_events deliberately omitted: outcome varies per MTA pairing;
  # filled into results/matrix.json by the harness, not asserted.
```

### 4.3 Baseline row discipline

A₁ (`\r\n.\r\n`) is the legitimate end-of-data marker and is **not an attack**. It is included as the sanity row: if the harness ever reports anything other than exactly 1 stub event for A₁ against any pairing, the harness itself is broken and all other results are suspect. The `family: baseline` flag marks this row; the matrix generator colours it differently in the report to avoid misreading.

---

## 5. Attack Harness

### 5.1 Implementation constraints

- Python 3.11+, **stdlib only** for the attack path.
- **Never `smtplib`** — it normalizes `\n` to `\r\n`, strips `\x00`, and generally defeats the entire project. Raw `socket` only.
- The SMTP state machine is minimal: `EHLO → MAIL FROM → RCPT TO → DATA → <carrier body with {SMUGGLED_BLOCK} substituted> → QUIT`.
- Carrier email template is a fixed multipart/alternative message with one placeholder `{SMUGGLED_BLOCK}` where the payload bytes splice in.

### 5.2 Core signature

```python
def run_case(pair: SenderReceiverPair, payload: Payload) -> CaseResult:
    """
    Send one carrier email through `pair` with `payload.bytes` spliced in.
    Records four ground-truth channels:
      - wire_pcap_path:     full SMTP conversation captured on labnet bridge
      - stub_events:        list of (MAIL_FROM, RCPT_TO, DATA) the stub saw
      - mta_queue_ids:      queue IDs observed in receiver's spool directory
      - imap_message_count: messages in target mailbox (demo-only oracle)
    """
```

A case is classified **vulnerable** when `len(stub_events) > 1` *or* `imap_message_count > 1`. Disagreement between the two is itself a finding and is logged, not hidden.

---

## 6. Ground-Truth Oracle

The oracle is two pieces that together give an MTA-independent, byte-level answer to "did the receiver see one email or two?"

### 6.1 Piece 1 — tcpdump sidecar

A minimal Alpine+tcpdump container captures every byte on `labnet` port 25 to `/pcaps/case-<id>.pcap`, one pcap per test case, named by case ID. This is the "what the receiver actually saw" record. Python `dpkt` or `scapy` opens these for replay and inspection.

### 6.2 Piece 2 — stub SMTP receiver

A ~80-line `asyncio` Python service that speaks SMTP correctly (`EHLO`, `MAIL FROM`, `RCPT TO`, `DATA`, proper numeric codes) but has **zero parser-differential behaviour** — because we wrote it and we know exactly how it counts. Every discrete `MAIL FROM → DATA → <end>` cycle is logged as one JSON event. The count of events is the scientific ground truth.

### 6.3 Test flow

```
1. Harness sends case X through [postfix-sender → postfix-receiver].
2. tcpdump captures wire bytes → results/pcaps/case-X.pcap.
3. Harness replays captured bytes against the stub receiver.
4. Stub reports: "I saw N discrete email transactions."
5. Classification:
   N > 1  ⇒ vulnerable
   N = 1  ⇒ sanitized somewhere (sender or receiver)
   N = 0  ⇒ receiver rejected outright
```

### 6.4 Why replay through the stub instead of counting MTA outputs

Real MTAs lie to us — Postfix accepts a smuggled email, queues two separate messages, and logs them with queue IDs that look almost identical to legitimate delivery; Exim's behaviour differs again. The stub gives a single consistent answer across MTA brands and versions: *these bytes, parsed naively, contained N email transactions*.

### 6.5 Sender-side sanitization handling

When the stub reports `N=1` for a payload we believed should smuggle, the first question is "did the sender sanitize the bytes before the wire?" The harness answers by byte-diffing `payloads.yaml`'s original `bytes_b64` against the `DATA` block in the pcap. If they differ, the cell is labelled `sanitized-by-sender` — **this is a finding, not a bug** — and the diff is attached to the case record.

### 6.6 Demo-only layer

For the live demo, a real Dovecot container receives mail from the receiving MTA. Running A₂ live produces **two actual emails** in a real mailbox when the harness sent one. This is the "aha moment" for the grader; it is not the scientific oracle.

---

## 7. Detection Layer

Two detectors, framed as a deliberate contrast so that the gap between them is itself a reportable finding.

### 7.1 Zeek — primary detector

**Why Zeek.** Zeek reconstructs TCP streams and exposes raw SMTP body bytes at the script layer *before* any normalization, which is exactly the layer the parser-differential lives in. Suricata's signature engine is line-oriented and would fight bare-`\r` and `\x00` patterns; Python SMTP proxies would work but are slower to write and less grader-impressive.

**The script** — `detect/gateway/smtp-smuggling.zeek` — does three things:

1. Hooks Zeek's built-in SMTP analyzer DATA event. Accumulates raw body bytes per connection ID.
2. Scans the buffer for **parser-ambiguous byte sequences around a dot**, not just the literal 13 paper payloads. Patterns:
   - `\n.\n` (bare LF dot bare LF)
   - `\r.\r` (bare CR dot bare CR)
   - `\r\n.\n`, `\n.\r\n` (mixed line endings)
   - Any `\x00` within 3 bytes of a `.` preceded by any line terminator
3. Raises a Zeek notice with connection 5-tuple, offending byte offset, and which pattern matched. Notices go to `results/zeek-notices/case-<id>.log` in structured form.

**Generic-by-construction.** The rule detects the *vulnerability class*, not the 13 example payloads. This is both why it will catch M2 fuzzer-discovered variants and why it is defensible in the report.

**First-time-user safety net.** The user has never used Zeek. A 30-minute primer lives at `docs/zeek-primer.md` with concrete commands, not links, and an M0 smoke test (`zeek -r smoke.pcap smtp-smuggling.zeek` on a hand-made 1-byte-smuggle pcap) runs on day 1. If Zeek turns out to be a wall, we swap in a Python SMTP proxy before time pressure hits.

### 7.2 Log parser — contrast detector

`detect/logs/parse_mail_log.py` tails `/var/log/mail.log` (Postfix) and `/var/spool/exim4/log/mainlog` (Exim) and flags:

- One SMTP connection producing multiple queue IDs (`250 2.0.0 Ok: queued as <qid>` twice).
- Duplicate `Message-ID:` headers within a short window.
- Unusual `Received:` header chains showing the same sender twice.

**Expected failure modes.** Each signal is a secondary symptom, not a primary one. The parser will miss every case where the sender sanitized, every case where the receiver silently dropped, and every rejected attack — all of which Zeek sees. The report publishes two columns (Zeek caught / log parser caught) and the *gap* is the finding: "defenders relying on MTA logs alone have a blind spot of this exact size."

### 7.3 Detection testing

Both detectors are tested against **the pcap corpus the oracle already produces**. Every test case generates `case-<id>.pcap` as a side effect; Zeek has a `zeek -r file.pcap` mode that reads pcaps exactly like live traffic, so detection tests are "run detector on each pcap and diff against expected_matrix.json." Live sniffing is only needed for the demo.

---

## 8. Testing Strategy

Four distinct test surfaces, each with its own purpose:

1. **`tests/test_harness.py`** — pytest, seconds. Proves the attack *code* works, not that the attack works. Payloads load from YAML without byte mutation; raw-socket writer round-trips through a memory buffer preserving every byte; carrier template substitution is byte-accurate. Catches "smtplib normalized my `\n`" bugs upfront.

2. **`tests/test_stub.py`** — sends hand-crafted byte sequences directly at the stub and asserts event counts. Baseline → 1; `\n.\n\r\nMAIL FROM...` → 2; truncated → 0. Catches a silently lying stub.

3. **`tests/test_matrix.py`** — parametrized over `payloads.yaml × pairings`. Spins the lab, runs cases, asserts oracle result matches `tests/expected_matrix.json`. On first M0/M1 run, the golden is empty and gets populated from actual observed runs; from then on it is a regression guard. If Debian silently bumps Postfix to 3.9, this fails loudly and prompts a report update rather than hiding the drift.

4. **`tests/test_detection.py`** — for every pcap in `results/pcaps/`, run Zeek and log parser; assert outputs match `expected_matrix.json`. Runs on every commit via pre-commit hook because detection rules regress silently.

**Explicitly out of regression coverage:** M2 fuzz-generated variants. They get manual write-ups in `results/m2-findings.md` rather than asserted tests, because by definition they may not reproduce between runs and that should not break the CI loop.

---

## 9. Canonical File Layout

```
ATM-Paper/
├── usenixsecurity25-wang-chuhan.pdf # already exists — the paper
├── README.md                        # how to run, how to demo, how to grade
├── reproduce.sh                     # one-command end-to-end for the demo
│
├── docs/
│   ├── specs/2026-04-14-smtp-smuggling-lab-design.md              # THIS FILE
│   ├── status.md                    # living M0/M1/M2 checkboxes
│   ├── zeek-primer.md               # 30-min "Zeek in anger" for first-timers
│   └── report/
│       ├── report.md                # the submittable writeup
│       └── figures/                 # auto-generated from results/
│
├── lab/
│   ├── podman-compose.yml           # labnet bridge, profiles per pairing
│   ├── postfix/
│   │   ├── Containerfile            # debian:12-slim + postfix
│   │   └── main.cf                  # smtpd_forbid_bare_newline = no
│   ├── exim/
│   │   ├── Containerfile
│   │   └── exim4.conf
│   ├── dovecot/
│   │   └── Containerfile            # demo-only IMAP oracle
│   ├── stub/
│   │   └── stub_smtpd.py            # wire-replay oracle (~80 lines)
│   └── tcpdump-sidecar/
│       └── Containerfile            # minimal alpine + tcpdump
│
├── payloads/
│   └── payloads.yaml                # A1–A13 + M2 discoveries, base64-encoded
│
├── harness/
│   ├── send.py                      # raw-socket SMTP client
│   ├── run_case.py                  # single-case orchestrator
│   ├── run_matrix.py                # full matrix driver
│   ├── oracle.py                    # pcap → stub replay → event count
│   └── render_matrix.py             # matrix.json → matrix.md + figures
│
├── detect/
│   ├── gateway/
│   │   └── smtp-smuggling.zeek      # primary Zeek script
│   └── logs/
│       └── parse_mail_log.py        # contrast detector
│
├── results/                         # git-committed evidence
│   ├── matrix.json                  # machine-readable matrix
│   ├── matrix.md                    # rendered matrix for the report
│   ├── pcaps/                       # per-case pcaps
│   ├── zeek-notices/                # per-case Zeek notice logs
│   └── m2-findings.md               # beyond-paper findings
│
└── tests/
    ├── test_harness.py
    ├── test_stub.py
    ├── test_matrix.py
    ├── test_detection.py
    └── expected_matrix.json         # golden regression
```

### 9.1 Conventions

- **`results/` is committed to git.** The evidence IS the project. `git log results/matrix.json` makes the M0→M1→M2 progression visible in history. Pcaps are ≤1 MB × ~60 cases = well under 100 MB, which Git handles fine.
- **Everything human-readable in the report is generated.** `harness/render_matrix.py` turns `results/matrix.json` into tables, coverage stats, and byte-diagram figures. No hand-edited tables in the report — they rot instantly.

---

## 10. Containment and Safety

- All traffic stays on the `labnet` Podman bridge. Nothing forwarded to the host except Dovecot IMAP on `127.0.0.1:1143` (demo only).
- Every outbound hostname in the test fixtures uses the `.test` reserved TLD. The harness refuses to run if any target resolves outside `10.0.0.0/8` / `labnet`.
- `reproduce.sh` must refuse to run if `podman network inspect labnet` shows any publicly-routable IP binding.
- All containers run with `--security-opt seccomp=unconfined` (user environment requires this; `seccomp.json` is broken locally).

---

## 11. Report and Demo Deliverables

### 11.1 Report (`docs/report/report.md`)

Target ~10 pages, rendered to PDF for submission. Sections:

1. Background — SMTP `DATA` phase and the end-of-data marker.
2. The parser-differential — paper's contribution in our words.
3. Lab architecture — Section 3 of this spec, condensed.
4. Results matrix — auto-generated from `results/matrix.json`.
5. Detection — Zeek rule explained, log-parser contrast quantified.
6. Beyond the paper — M2 findings (if any).
7. Limitations and future work.
8. References.

### 11.2 Demo (live, ≤10 minutes)

1. `podman-compose up` — 60 seconds.
2. `./attack.sh A2` — send one smuggled email.
3. Open Thunderbird / `mutt` on Dovecot mailbox — two emails visible.
4. `cat results/zeek-notices/latest.log` — Zeek notice with byte offset.
5. `cat results/logs/latest-parse.log` — log parser *missed* it (or caught a secondary symptom). Contrast stated aloud.
6. `python harness/run_matrix.py` — full matrix regenerated in under 15 minutes (optional depending on grader's time).

---

## 12. Open Risks

- **Zeek first-time-user risk.** Mitigated by the M0 day-1 smoke test. If Zeek fights back, swap in a Python SMTP proxy detector; the detection-layer interface (pcap in → JSON notice out) is stable regardless of tool.
- **Debian silently upgrading Postfix/Exim.** Mitigated by pinning to `debian:12-slim` (not `debian:stable-slim`) and by `test_matrix.py` asserting against a golden file — any drift fails loudly.
- **Host seccomp.json broken.** Mitigated by `--security-opt seccomp=unconfined` on every container.
- **Podman rootless `NET_RAW` for Zeek.** Zeek needs `NET_ADMIN` and `NET_RAW`; may require `--cap-add` or running the Zeek container in non-rootless mode. If rootless fails, document the rootful fallback in the README rather than burning hours on it.
- **M2 is inherently open-ended.** Exit criterion is "you tried and wrote up what happened," not "you found a new CVE." No risk of falling short as long as the write-up exists.

---

## 13. What This Spec Is Not

This spec does not contain task-level implementation detail — concrete file contents, exact function bodies, per-step commands, or dependency ordering between construction steps. That belongs in a follow-on implementation plan, which is the next document produced using this spec as input.
