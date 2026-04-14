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

- **Spoofing domains the researcher does not own.** Every external-target test uses only researcher-owned sending accounts on researcher-owned domains (or free-mail accounts where the researcher controls both sender and recipient mailboxes). No forged `From:` of a third-party identity to a non-consenting recipient, ever.
- **Delivering smuggled payloads to non-consenting recipients.** All recipient addresses in external tests belong to the researcher. This is the paper's Section 9.1 ethical discipline and is also what keeps the work inside every major bug bounty program's scope.
- Building a hardened / production-grade detector. The Zeek rule is for coursework and does not need to handle adversarial evasion beyond the paper's and our own fuzzer's variants.
- DKIM/SPF/DMARC *infrastructure* reproduction. Authentication is out of scope except insofar as A₁ (baseline `\r\n.\r\n`) must successfully deliver a normal email.

### Explicitly In Scope (new)

- **Live probes against real email providers**, bounded by the non-goals above. The paper's public-service measurement study is *reproducible*, and the interesting follow-on questions — "did the patches hold N months later?" and "does the fix rely on an assumption a fuzzer can violate?" — require touching production infrastructure. The project includes a deliberately separate external-probe subsystem for this (architecture in §3.1, milestone in §2.M3, guardrails in §10.2).

---

## 2. Tiered Milestones

The project is structured as four nested tiers (M0 through M3). Each tier has a **hard exit criterion**: if hit, the project is submittable at that tier's level. A `git tag milestone-M<N>-complete` is created at each exit to make the floor explicit and recoverable. M3 is **default-off** via a kill-switch file (see §10.2) so that M0–M2 can always be built, committed, and submitted without any external probes running.

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

### M3 — Live Bypass Hunt — target: remaining time after week 3, or post-submission continuation

**Scope:** Probe real, live email providers with the full M1+M2 payload corpus plus assumption-violating encoding mutants, looking for *new* variants not in the paper that still smuggle against providers the paper flagged as patched. This tier is framed as a **fix-study hunt**, not a fuzz-blast: we pick a target, read its published patch notes or infer its fix from observed behaviour, form a hypothesis about the assumption the fix relies on, then generate payloads that violate exactly that assumption.

**Target allowlist** (lives in `external/targets.yaml`, each entry recording program URL, in-scope statement, last-verified-active date, rate limit, contact email):

1. **Fastmail** — H1 program, paper found bare-`\r` variant, historically responsive. Primary target for bypass hunt.
2. **Yandex** — own program at yandex.com/bugbounty, paper found vulnerable.
3. **Sina / Sohu** — CNVD / CN-CERT responsible disclosure, paper found both vulnerable; interesting because their fixes (if any) are undocumented.
4. **Gmail VRP** — Google Bug Hunters, mail-infrastructure scope explicit. Paper flagged as not-vulnerable; hunt target is any bypass of the specific bytes they filter.
5. **Microsoft MSRC** — Outlook / Office 365, mail scope explicit. Paper flagged as not-vulnerable.
6. **Tencent SRC** — qq.com / Tencent Mail, paper flagged as not-vulnerable.
7. **Anything the researcher adds** after verifying (a) an active bounty / disclosure program, (b) mail infrastructure in scope, (c) researcher owns accounts on both send and receive sides.

**Assumption-bypass hypotheses, in order of expected payoff:**

1. **Fix operates on ASCII only.** Violate with UTF-8 overlong encoding of `.` (`\xc0\xae`, `\xe0\x80\xae`, `\xf0\x80\x80\xae`), fullwidth `．` (U+FF0E), or Unicode confusables that parser libraries sometimes treat as `.`.
2. **Fix scans a bounded prefix of the body.** Violate by padding the carrier body with 128 KB of legitimate MIME, then placing the smuggling payload after the scan window.
3. **Fix normalizes line endings per SMTP-line.** Violate by placing the smuggle across a TCP segment boundary so the MTA sees `\r\n.\r` in segment 1 and `\n MAIL FROM...` in segment 2.
4. **Fix checks plain SMTP DATA only.** Violate by delivering via `CHUNKING` / `BDAT` extension, where the parser path may differ from `DATA`.
5. **Fix operates on 7-bit, strips high bits before inspection.** Violate by delivering via `8BITMIME` with a high-bit-set dot.
6. **Fix checks raw body only.** Violate by encoding the smuggling bytes as quoted-printable (`=0A=2E=0A`) or base64 in a MIME part that the receiver decodes after the smuggling check.
7. **Fix assumes CR and LF can be treated symmetrically.** Violate with mixed-ending payloads that weren't in the paper: `\r\r\n.\r\r\n`, `\n\r.\n\r`, etc. — the fuzzer's search space.

**Methodology discipline:** For each hypothesis, the report records *before probing*: the assumption statement, the predicted outcome, the specific payload that tests it, and the expected stub-event count if the hypothesis holds. We record the actual result next to the prediction. This is the "study the fix, attack the assumption" discipline from the research-mindset notes — a negative result is still a publishable finding ("provider X's patch is robust against assumption class Y"), and a positive result with pre-registered hypothesis beats "I found something" with no theory.

**Rate limits and accounting.** `external/probe-log.jsonl` is append-only, timestamps every send, and the harness sleeps to enforce **≥60 seconds between sends per provider** (the paper used 30; we're double-conservative). A daily cap of 50 sends per provider caps total blast radius. The log is committed to git so the probe history is auditable.

**Disclosure plan — written before the first probe, not after.** Located at `external/disclosure-plan.md` and checked by the harness on startup. Standard terms: 90-day embargo from report to public disclosure, initial report via the program's official channel, CVE requested through MITRE or the provider's CNA, coordinated publication with the provider's timeline.

**Exit criterion:** Any of:
- (a) Full A₁–A₁₃ rerun against the allowlist with results recorded (reproduction of the paper);
- (b) At least one assumption hypothesis tested against at least one provider with the result written up as a finding;
- (c) A documented "we tried, the provider rate-limited us, here's what we learned" negative result.

All three are valid M3 exits. The only way to fail M3 is to skip the write-up.

---

## 3. Architecture

### 3.1 Container topology

Two independent subsystems: an **isolated lab** (M0–M2) on the Podman bridge `labnet` with no egress, and a **separate external probe** (M3) with deliberate egress to an allowlist of real providers. The two share no containers, no networks, and no credentials. Every container runs with `--security-opt seccomp=unconfined` (user's local `seccomp.json` is broken; this removes a class of runtime errors upfront).

**Lab subsystem (M0–M2, no egress):**

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
                          ← ─ ─ ─ ─ ─ ─ labnet (no egress) ─ ─ ─ ─ ─ ─ →
```

**External-probe subsystem (M3 only, default-off):**

```
 ┌───────────────┐          SMTP submission / TLS          ┌────────────────────────┐
 │ external-     │  ─────────────────────────────────────► │ Fastmail / Yandex /    │
 │ harness       │          (rate-limited, logged)         │ Sina / Sohu / Gmail /  │
 │ (reuses       │  ◄──────────────────────────────────── │ Outlook / Tencent ...  │
 │  harness/     │         IMAP verification &             │ (researcher-owned      │
 │  send.py)     │         mailbox read-back               │  accounts only)        │
 └───────────────┘                                         └────────────────────────┘
        │
        ▼
 external/probe-log.jsonl    ← append-only audit trail
 external/ENABLED            ← kill switch: absent = harness refuses to run
```

The external harness is the **same Python module** as the lab harness (`harness/send.py`) with a different target hostname and a different runtime-guard module (`harness/external_guard.py`) that enforces rate limits, account-ownership verification, and the kill switch before any `socket.sendall`. One codebase, two runtime profiles.

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

- id: M3-utf8-overlong-dot
  bytes_b64: "DQrAriANCg=="           # "\r\n\xc0\xae \r\n" — UTF-8 overlong '.'
  family: m3-encoding-bypass
  encoding: utf8-overlong
  hypothesis: "Fix operates on ASCII-only dot scanning; UTF-8 overlong slips past."
  paper_ref: null                     # not in paper — M3 discovery candidate
  scope: external-only                # the lab harness will refuse to test this
```

Any payload tagged `scope: external-only` is only runnable by `harness/run_external.py`, not by `harness/run_matrix.py`. Lab matrix tests that category-filter to `scope != external-only` stay clean even when the M3 payload set grows.

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
│   ├── send.py                      # raw-socket SMTP client (used by both lab & external)
│   ├── run_case.py                  # single-case orchestrator (lab)
│   ├── run_matrix.py                # full matrix driver (lab)
│   ├── oracle.py                    # pcap → stub replay → event count
│   ├── render_matrix.py             # matrix.json → matrix.md + figures
│   ├── external_guard.py            # M3 kill-switch / allowlist / rate-limit
│   └── run_external.py              # M3 probe driver (refuses to run if guards fail)
│
├── detect/
│   ├── gateway/
│   │   └── smtp-smuggling.zeek      # primary Zeek script
│   └── logs/
│       └── parse_mail_log.py        # contrast detector
│
├── external/                        # M3 external-probe subsystem (default-off)
│   ├── ENABLED                      # gitignored — its absence disables the harness
│   ├── targets.yaml                 # provider allowlist (URL, scope, rate limit, date)
│   ├── accounts.yaml                # researcher credentials (gitignored, perms 600)
│   ├── disclosure-plan.md           # 90-day embargo + reporting channels, required
│   └── probe-log.jsonl              # append-only audit trail of every external send
│
├── results/                         # git-committed evidence
│   ├── matrix.json                  # machine-readable lab matrix (M0–M2)
│   ├── matrix.md                    # rendered lab matrix for the report
│   ├── pcaps/                       # per-case pcaps
│   ├── zeek-notices/                # per-case Zeek notice logs
│   ├── m2-findings.md               # beyond-paper lab findings
│   └── m3-findings.md               # live-provider findings (M3)
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

Containment rules are split into two regimes. The lab regime (§10.1) is strict and applies to M0–M2. The external regime (§10.2) is deliberately different because external probing requires egress; its safety comes from tight account-ownership and rate-limit guardrails, not from network isolation.

### 10.1 Lab regime (M0–M2)

- All traffic stays on the `labnet` Podman bridge. Nothing forwarded to the host except Dovecot IMAP on `127.0.0.1:1143` (demo only).
- Every outbound hostname in lab test fixtures uses the `.test` reserved TLD. The lab harness refuses to run if any lab target resolves outside `10.0.0.0/8` / `labnet`.
- `reproduce.sh` must refuse to run if `podman network inspect labnet` shows any publicly-routable IP binding.
- All containers run with `--security-opt seccomp=unconfined` (user environment requires this; `seccomp.json` is broken locally).

### 10.2 External regime (M3 only)

The external harness runs in its own container with direct egress but is gated by **four independent guards, all of which must pass** before any byte is written to a socket:

1. **Kill switch.** The file `external/ENABLED` must exist. If it doesn't, the harness prints the guard list and exits. The file is gitignored with a single line (`external/ENABLED`) so it never accidentally lands in a commit and never gets pushed to a grader's machine in an "on" state.
2. **Target allowlist.** The target hostname must appear in `external/targets.yaml` with a non-expired `last-verified-active` date. Any other hostname is refused. Localhost, `.test`, and RFC1918 addresses are also refused by the external harness — it is strictly for external probes.
3. **Account ownership proof.** Before any send, the harness connects via IMAP to the *sender* account and to the *recipient* account using credentials in `external/accounts.yaml` (file-permissions 600, gitignored), verifies login, and aborts if either fails. This is the "you own both ends" enforcement. No IMAP login = no send.
4. **Rate limiter.** Minimum 60 seconds between sends per provider, daily cap of 50 sends per provider, both enforced in `harness/external_guard.py` by checking `external/probe-log.jsonl` before each send. Exceeding either cap aborts with a clear error.

Additionally:

- **Every send is logged append-only** to `external/probe-log.jsonl` with timestamp, target, payload id, sender account, recipient account, outcome, and a hash of the exact bytes sent. This log is committed to git so the probe history is auditable and so a grader or bounty triage team can verify exactly what was sent when.
- **No spoofing.** The harness refuses to send if the `MAIL FROM` envelope address differs from the authenticated IMAP username. The carrier email's `From:` header must equal the envelope sender. This is enforced by `external_guard.py`, not by convention.
- **Disclosure plan must exist.** `external/disclosure-plan.md` must exist and be non-empty before the harness runs. The file's existence is checked, not its content, but the check forces the researcher to at least commit a plan before the first probe.
- **Provider kill-switch.** Any single HTTP 4xx, 5xx, 421 SMTP code, or timeout against a given provider auto-disables that provider in `external/probe-log.jsonl` for the remainder of the day. Re-enabling requires an explicit `--reset-provider <name>` flag on the harness.

The result is a subsystem that can reach real providers, that leaves an auditable trail of exactly what it sent, and that **physically cannot run** without the researcher taking four explicit affirmative steps (create ENABLED file, populate targets, populate accounts, write disclosure plan).

---

## 11. Report and Demo Deliverables

### 11.1 Report (`docs/report/report.md`)

Target ~12 pages with the M3 content, rendered to PDF for submission. Sections:

1. Background — SMTP `DATA` phase and the end-of-data marker.
2. The parser-differential — paper's contribution in our words.
3. Lab architecture — Section 3 of this spec, condensed.
4. Results matrix — auto-generated from `results/matrix.json`.
5. Detection — Zeek rule explained, log-parser contrast quantified.
6. Beyond the paper (lab) — M2 fuzzer + patched-version findings.
7. **Live provider findings** — M3 section, present only if M3 has run. Two subsections:
   - **7.1 Paper reproduction N months later** — did the patches hold against A₁–A₁₃ for the providers the paper flagged vulnerable? Did any provider the paper flagged non-vulnerable show behaviour change?
   - **7.2 Assumption-bypass probes** — one paragraph per hypothesis: assumption statement, payload family, predicted outcome, actual outcome, status.
8. **Ethics and methodology** — M3 section. Cites the paper's Section 9.1, documents the four guards (§10.2), links to `external/probe-log.jsonl` and `external/disclosure-plan.md` as evidence.
9. Limitations and future work.
10. References.

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
- **M3 grading-policy risk.** Running probes against real third-party services may fall outside what the course explicitly permits even when the providers' bounty programs allow it. Mitigation: M3 is default-off (the `external/ENABLED` kill switch is gitignored and absent by default), so the graded artifact can be M0+M1+M2 only. Running M3 is an explicit additional step the researcher takes after verifying course permission; it lands as a separate tag `milestone-M3-complete` and a separate `results/m3-findings.md` file rather than being merged into the lab matrix.
- **M3 account-banning risk.** Providers may flag researcher accounts as abusive even for in-scope testing, costing access. Mitigation: conservative rate limit (60s/send, 50/day cap), per-provider auto-disable on first 4xx/5xx/421/timeout, and a pre-probe IMAP verification step that confirms the account is reachable before burning a send attempt.
- **M3 disclosure-timeline risk.** Finding a real bypass starts a coordinated-disclosure clock; the report cannot publish details before the embargo ends. Mitigation: `external/disclosure-plan.md` is written *before* the first probe and specifies what can vs. cannot appear in the coursework report if a finding is live-embargoed at submission time (redacted payload, named provider, dated findings-not-yet-disclosed section).

---

## 13. What This Spec Is Not

This spec does not contain task-level implementation detail — concrete file contents, exact function bodies, per-step commands, or dependency ordering between construction steps. That belongs in a follow-on implementation plan, which is the next document produced using this spec as input.
