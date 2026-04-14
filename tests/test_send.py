"""Harness tests against the stub receiver.

Note: both A1 (\\n.\\n) and A5 (\\r\\n.\\n) go through the carrier builder
which wraps them in prefix/suffix text. Against the RFC-strict stub,
neither payload's inline line-ending variant is treated as a DATA
terminator, so the entire carrier body is consumed as one email. The
stub is intentionally non-vulnerable — smuggling effects only manifest
when a vulnerable real MTA sits between the harness and the stub.

The 'baseline delivery' sanity check uses an empty smuggled_block: a
plain carrier with no smuggled payload should always deliver as
exactly one email to any correct receiver, real or stub.
"""
import asyncio
import json
from dataclasses import replace
from pathlib import Path

import pytest

from harness.payloads import Payload, load_payloads
from harness.send import send_case
from lab.stub.stub_smtpd import StubSmtpd


@pytest.mark.asyncio
async def test_baseline_empty_smuggled_block_delivers_one_email(tmp_path):
    # Sanity check: harness + carrier + stub on an empty smuggled_block
    # should produce exactly 1 data_complete event. This is the proof
    # that the send path itself works end-to-end; the smuggling cases
    # are additional.
    events = tmp_path / "events.jsonl"
    stub = StubSmtpd("127.0.0.1", 3538, events)
    await stub.start()
    try:
        # Construct a Payload with empty bytes on the fly; no base64 parsing.
        empty = Payload(
            id="BASELINE",
            raw_bytes=b"",
            family="baseline",
            paper_ref="none",
            scope="lab",
        )
        await asyncio.to_thread(
            send_case,
            "127.0.0.1",
            3538,
            "alice@labnet.test",
            "bob@labnet.test",
            empty,
        )
        await asyncio.sleep(0.1)
    finally:
        await stub.stop()
    lines = [json.loads(l) for l in events.read_text().strip().split("\n") if l]
    data_events = [l for l in lines if l["type"] == "data_complete"]
    assert len(data_events) == 1
    assert data_events[0]["body_len"] > 0


@pytest.mark.asyncio
async def test_a1_against_rfc_strict_stub_produces_one_event(tmp_path):
    # Against the RFC-strict stub, A1 (\n.\n) is NOT a valid terminator,
    # so the entire carrier is read as one DATA body. Exactly one
    # data_complete event. This does NOT prove the attack works — it
    # proves the harness and stub interact cleanly, and the stub is
    # conservatively non-vulnerable (good: the stub is an oracle).
    events = tmp_path / "events.jsonl"
    stub = StubSmtpd("127.0.0.1", 3540, events)
    await stub.start()
    try:
        payloads = {p.id: p for p in load_payloads("payloads/payloads.yaml")}
        await asyncio.to_thread(
            send_case,
            "127.0.0.1",
            3540,
            "alice@labnet.test",
            "bob@labnet.test",
            payloads["A1"],
        )
        await asyncio.sleep(0.1)
    finally:
        await stub.stop()
    lines = [json.loads(l) for l in events.read_text().strip().split("\n") if l]
    data_events = [l for l in lines if l["type"] == "data_complete"]
    assert len(data_events) == 1


@pytest.mark.asyncio
async def test_a5_against_rfc_strict_stub_produces_one_event(tmp_path):
    events = tmp_path / "events.jsonl"
    stub = StubSmtpd("127.0.0.1", 3541, events)
    await stub.start()
    try:
        payloads = {p.id: p for p in load_payloads("payloads/payloads.yaml")}
        await asyncio.to_thread(
            send_case,
            "127.0.0.1",
            3541,
            "alice@labnet.test",
            "bob@labnet.test",
            payloads["A5"],
        )
        await asyncio.sleep(0.1)
    finally:
        await stub.stop()
    lines = [json.loads(l) for l in events.read_text().strip().split("\n") if l]
    data_events = [l for l in lines if l["type"] == "data_complete"]
    assert len(data_events) == 1
