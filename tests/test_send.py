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
async def test_harness_sends_non_terminator_payload_as_one_email(tmp_path):
    # Using A2 (\n.\n) which is NOT the strict RFC terminator, the stub
    # should see exactly one complete DATA transaction (terminated by
    # the real \r\n.\r\n at the end of the carrier suffix). Note: A1
    # (\r\n.\r\n) is the legitimate terminator and is not meaningful
    # when sent directly to the stub without a real MTA in the middle,
    # because the carrier builder's suffix also contains SMTP-shaped
    # text that the stub would then try to parse as a follow-on
    # transaction. A1's semantics only hold when routed through a real
    # MTA that accepts the full DATA body atomically.
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
            payloads["A2"],
        )
        await asyncio.sleep(0.1)
    finally:
        await stub.stop()
    lines = [json.loads(l) for l in events.read_text().strip().split("\n") if l]
    data_events = [l for l in lines if l["type"] == "data_complete"]
    assert len(data_events) == 1
    assert data_events[0]["body_len"] > 0


@pytest.mark.asyncio
async def test_a2_against_rfc_strict_stub_produces_one_event(tmp_path):
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
