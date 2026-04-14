"""Oracle tests — verify pcap-to-stub replay pipeline."""
from pathlib import Path

import dpkt
import pytest

from harness.oracle import (
    count_data_complete_events,
    extract_smtp_data_bytes,
    replay_against_stub,
)
from lab.stub.stub_smtpd import StubSmtpd


def _build_minimal_smtp_pcap(tmp_path: Path, body: bytes) -> Path:
    """Build a tiny pcap containing one SMTP session with the given
    DATA body. Used as a deterministic fixture for oracle unit tests."""
    out = tmp_path / "case.pcap"
    f = open(out, "wb")
    writer = dpkt.pcap.Writer(f)

    def pkt(sport: int, dport: int, payload: bytes, seq: int) -> bytes:
        tcp = dpkt.tcp.TCP(
            sport=sport, dport=dport,
            seq=seq, ack=1,
            flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH,
            off_x2=0x50,
        )
        tcp.data = payload
        ip = dpkt.ip.IP(
            src=bytes([10, 0, 0, 1]),
            dst=bytes([10, 0, 0, 2]),
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
        b"EHLO test.example\r\n",
        b"MAIL FROM:<a@a.test>\r\n",
        b"RCPT TO:<b@b.test>\r\n",
        b"DATA\r\n",
        body,
        b"QUIT\r\n",
    ]
    seq = 1
    for payload in commands:
        writer.writepkt(pkt(40000, 25, payload, seq))
        seq += len(payload)
    writer.close()
    f.close()
    return out


def test_extract_smtp_data_from_synthetic_pcap(tmp_path):
    body = b"Subject: test\r\n\r\nhello\r\n.\r\n"
    pcap_path = _build_minimal_smtp_pcap(tmp_path, body)
    extracted = extract_smtp_data_bytes(pcap_path)
    assert body in extracted
    assert b"EHLO test.example\r\n" in extracted
    assert b"QUIT\r\n" in extracted


@pytest.mark.asyncio
async def test_replay_against_stub_produces_one_event(tmp_path):
    body = b"Subject: one\r\n\r\nline\r\n.\r\n"
    pcap_path = _build_minimal_smtp_pcap(tmp_path, body)

    events_path = tmp_path / "events.jsonl"
    stub = StubSmtpd("127.0.0.1", 3560, events_path)
    await stub.start()
    try:
        await replay_against_stub(pcap_path, stub_host="127.0.0.1", stub_port=3560)
    finally:
        await stub.stop()
    assert count_data_complete_events(events_path) == 1


@pytest.mark.asyncio
async def test_replay_against_stub_counts_two_back_to_back_emails(tmp_path):
    body = (
        b"Subject: first\r\n\r\nfirst-body\r\n.\r\n"
        b"MAIL FROM:<c@c.test>\r\n"
        b"RCPT TO:<d@d.test>\r\n"
        b"DATA\r\n"
        b"Subject: second\r\n\r\nsecond-body\r\n.\r\n"
    )
    pcap_path = _build_minimal_smtp_pcap(tmp_path, body)

    events_path = tmp_path / "events.jsonl"
    stub = StubSmtpd("127.0.0.1", 3561, events_path)
    await stub.start()
    try:
        await replay_against_stub(pcap_path, stub_host="127.0.0.1", stub_port=3561)
    finally:
        await stub.stop()
    assert count_data_complete_events(events_path) == 2
