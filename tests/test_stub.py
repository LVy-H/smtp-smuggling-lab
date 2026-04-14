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
    stub = await _run_stub_on_port(events, 3525)
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
        await asyncio.to_thread(_send_raw, 3525, payload)
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
    stub = await _run_stub_on_port(events, 3526)
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
        await asyncio.to_thread(_send_raw, 3526, payload)
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
    stub = await _run_stub_on_port(events, 3527)
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
        await asyncio.to_thread(_send_raw, 3527, payload)
        await asyncio.sleep(0.1)
    finally:
        await stub.stop()
    lines = [json.loads(l) for l in events.read_text().strip().split("\n") if l]
    data_events = [l for l in lines if l["type"] == "data_complete"]
    assert len(data_events) == 2
