"""Single-case orchestrator. Runs one payload through the live lab
and captures all ground-truth channels."""
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
    pair: str
    wire_pcap_path: str
    stub_event_count: int
    maildir_file_count: int
    classification: str


def _maildir_count(container: str, user: str = "bob") -> int:
    """Count files in /home/<user>/Maildir/new inside the container."""
    result = subprocess.run(
        ["podman", "exec", container, "sh", "-c",
         f"ls /home/{user}/Maildir/new 2>/dev/null | wc -l"],
        capture_output=True,
        text=True,
        check=False,
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


def _set_tcpdump_case_marker(case_id: str) -> None:
    subprocess.run(
        ["podman", "exec", "tcpdump-sidecar", "sh", "-c",
         f"echo {case_id} > /pcaps/current-case.txt"],
        check=True,
    )


def _copy_pcap_out(case_id: str, dest: Path) -> None:
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
    # 1. Clear the receiver's Maildir so counts are case-scoped
    _clear_maildir("postfix-receiver")

    # 2. Mark the tcpdump case id so the sidecar starts a new pcap
    _set_tcpdump_case_marker(case_id)
    time.sleep(0.5)

    # 3. Send the case through the live lab
    await asyncio.to_thread(
        send_case,
        sender_host, sender_port,
        envelope_from, envelope_to,
        payload,
    )

    # 4. Wait for receiver to queue, deliver, and settle
    time.sleep(2.5)

    # 5. Copy pcap to host results dir
    pcap_dest = results_dir / "pcaps" / f"case-{case_id}.pcap"
    _copy_pcap_out(case_id, pcap_dest)

    # 6. Replay captured bytes through the stub oracle
    events_path = results_dir / "stub-events" / f"case-{case_id}.jsonl"
    events_path.parent.mkdir(parents=True, exist_ok=True)
    stub = StubSmtpd("127.0.0.1", 3600, events_path)
    await stub.start()
    try:
        await replay_against_stub(pcap_dest, stub_host="127.0.0.1", stub_port=3600)
    finally:
        await stub.stop()
    stub_count = count_data_complete_events(events_path)

    # 7. Count delivered emails in the receiver's Maildir
    maildir_count = _maildir_count("postfix-receiver")

    # 8. Classify
    if stub_count > 1 or maildir_count > 1:
        classification = "vulnerable"
    elif stub_count == 1 and maildir_count == 1:
        classification = "not-vulnerable"
    elif stub_count == 1 and maildir_count == 0:
        classification = "sanitized-or-dropped"
    else:
        classification = f"unknown-stub={stub_count}-maildir={maildir_count}"

    return CaseResult(
        case_id=case_id,
        payload_id=payload.id,
        pair="postfix->postfix",
        wire_pcap_path=str(pcap_dest),
        stub_event_count=stub_count,
        maildir_file_count=maildir_count,
        classification=classification,
    )
