"""Single-case orchestrator. Runs one payload through the live lab
and captures ground-truth channels from both sender-side and
receiver-side tcpdump sidecars.

In M0 the oracle replayed the receiver-side pcap, which showed
post-relay (already-normalized) bytes. In M1 we replay the
sender-side pcap (raw harness->sender bytes), which preserves the
original smuggling attempt and gives a more accurate stub count.
"""
from __future__ import annotations

import asyncio
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from harness.oracle import count_data_complete_events, replay_against_stub
from harness.payloads import Payload
from harness.send import send_case
from lab.stub.stub_smtpd import StubSmtpd


@dataclass
class CaseResult:
    case_id: str
    payload_id: str
    pair: str  # one of: p2p, p2e, e2p, e2e
    wire_pcap_sender: str
    wire_pcap_receiver: str
    stub_event_count_sender: int
    stub_event_count_receiver: int
    maildir_file_count: int
    classification: str


_SENDER_SIDECAR_BY_PAIR = {
    "p2p": "tcpdump-sender-postfix",
    "p2e": "tcpdump-sender-postfix",
    "e2p": "tcpdump-sender-exim",
    "e2e": "tcpdump-sender-exim",
}
_RECEIVER_SIDECAR_BY_PAIR = {
    "p2p": "tcpdump-receiver-postfix",
    "p2e": "tcpdump-receiver-exim",
    "e2p": "tcpdump-receiver-postfix",
    "e2e": "tcpdump-receiver-exim",
}
_RECEIVER_CONTAINER_BY_PAIR = {
    "p2p": "postfix-receiver",
    "p2e": "exim-receiver",
    "e2p": "postfix-receiver",
    "e2e": "exim-receiver",
}


def _maildir_count(container: str, user: str = "bob") -> int:
    result = subprocess.run(
        ["podman", "exec", container, "sh", "-c",
         f"ls /home/{user}/Maildir/new 2>/dev/null | wc -l"],
        capture_output=True, text=True, check=False,
    )
    try:
        return int(result.stdout.strip() or "0")
    except ValueError:
        return 0


def _clear_maildir(container: str, user: str = "bob") -> None:
    subprocess.run(
        ["podman", "exec", container, "sh", "-c",
         f"rm -f /home/{user}/Maildir/new/*"],
        check=False,
    )


def _set_case_marker(sidecar_container: str, subdir: str, case_id: str) -> None:
    """Tell a tcpdump sidecar to start a new pcap named case-<id>.pcap.
    `subdir` is 'sender' or 'receiver'."""
    subprocess.run(
        ["podman", "exec", sidecar_container, "sh", "-c",
         f"mkdir -p /pcaps/{subdir} && echo {case_id} > /pcaps/{subdir}/current-case.txt"],
        check=True,
    )


def _copy_pcap_out(sidecar_container: str, subdir: str, case_id: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["podman", "cp",
         f"{sidecar_container}:/pcaps/{subdir}/case-{case_id}.pcap",
         str(dest)],
        check=True,
    )


async def run_case(
    case_id: str,
    payload: Payload,
    pair: str,
    sender_host: str = "127.0.0.1",
    sender_port: int = 2525,
    envelope_from: str = "alice@labnet.test",
    envelope_to: str = "bob@labnet.test",
    results_dir: Path = Path("results"),
) -> CaseResult:
    assert pair in ("p2p", "p2e", "e2p", "e2e"), f"unknown pair {pair}"
    sender_sidecar = _SENDER_SIDECAR_BY_PAIR[pair]
    receiver_sidecar = _RECEIVER_SIDECAR_BY_PAIR[pair]
    receiver_container = _RECEIVER_CONTAINER_BY_PAIR[pair]

    _clear_maildir(receiver_container)
    _set_case_marker(sender_sidecar, "sender", case_id)
    _set_case_marker(receiver_sidecar, "receiver", case_id)
    time.sleep(0.5)

    try:
        await asyncio.to_thread(
            send_case,
            sender_host, sender_port,
            envelope_from, envelope_to,
            payload,
        )
    except Exception as e:
        # Some MTAs reject outright; still capture whatever pcap exists
        print(f"  send raised: {type(e).__name__}: {e}")

    time.sleep(2.5)

    pcap_sender = results_dir / "pcaps" / f"case-{case_id}-sender.pcap"
    pcap_receiver = results_dir / "pcaps" / f"case-{case_id}-receiver.pcap"
    try:
        _copy_pcap_out(sender_sidecar, "sender", case_id, pcap_sender)
    except subprocess.CalledProcessError:
        pcap_sender.parent.mkdir(parents=True, exist_ok=True)
        pcap_sender.write_bytes(b"")
    try:
        _copy_pcap_out(receiver_sidecar, "receiver", case_id, pcap_receiver)
    except subprocess.CalledProcessError:
        pcap_receiver.parent.mkdir(parents=True, exist_ok=True)
        pcap_receiver.write_bytes(b"")

    stub_events_dir = results_dir / "stub-events"
    stub_events_dir.mkdir(parents=True, exist_ok=True)

    sender_events = stub_events_dir / f"case-{case_id}-sender.jsonl"
    stub_s = StubSmtpd("127.0.0.1", 3600, sender_events)
    await stub_s.start()
    try:
        if pcap_sender.stat().st_size > 0:
            await replay_against_stub(pcap_sender, "127.0.0.1", 3600)
    finally:
        await stub_s.stop()
    stub_count_sender = count_data_complete_events(sender_events)

    receiver_events = stub_events_dir / f"case-{case_id}-receiver.jsonl"
    stub_r = StubSmtpd("127.0.0.1", 3601, receiver_events)
    await stub_r.start()
    try:
        if pcap_receiver.stat().st_size > 0:
            await replay_against_stub(pcap_receiver, "127.0.0.1", 3601)
    finally:
        await stub_r.stop()
    stub_count_receiver = count_data_complete_events(receiver_events)

    maildir_count = _maildir_count(receiver_container)

    if stub_count_sender > 1 or maildir_count > 1:
        classification = "vulnerable"
    elif stub_count_sender == 1 and maildir_count == 1:
        classification = "not-vulnerable"
    elif stub_count_sender == 1 and maildir_count == 0:
        classification = "sanitized-or-dropped"
    elif stub_count_sender == 0 and maildir_count == 0:
        classification = "rejected-by-receiver"
    elif stub_count_sender == 0 and maildir_count == 1:
        classification = "not-vulnerable"
    else:
        classification = f"unknown-sender={stub_count_sender}-maildir={maildir_count}"

    return CaseResult(
        case_id=case_id,
        payload_id=payload.id,
        pair=pair,
        wire_pcap_sender=str(pcap_sender),
        wire_pcap_receiver=str(pcap_receiver),
        stub_event_count_sender=stub_count_sender,
        stub_event_count_receiver=stub_count_receiver,
        maildir_file_count=maildir_count,
        classification=classification,
    )
