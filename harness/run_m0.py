"""M0 end-to-end runner. Brings up the lab (assumed running), runs
the baseline plus every payload through run_case, invokes Zeek on
each captured pcap, and prints a pass/fail summary matching the
M0 exit criteria in docs/status.md.

Usage:
    python -m harness.run_m0
Exit code 0 on pass, 1 on any failure.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import sys
from pathlib import Path

from harness.payloads import Payload, load_payloads
from harness.run_case import CaseResult, run_case


ZEEK_IMAGE = "docker.io/zeek/zeek:lts"
ZEEK_STAGE = Path("/tmp/m0-zeek-run")
REPO = Path(__file__).resolve().parents[1]


def _run_zeek_on_pcap(pcap_path: Path) -> str:
    """Run Zeek on a pcap in a container and return notice.log text."""
    pcaps = ZEEK_STAGE / "pcaps"
    scripts = ZEEK_STAGE / "scripts"
    work = ZEEK_STAGE / "work"
    for d in (pcaps, scripts, work):
        d.mkdir(parents=True, exist_ok=True)
    for old in work.iterdir():
        old.unlink()
    shutil.copy(pcap_path, pcaps / pcap_path.name)
    shutil.copy(
        REPO / "detect/gateway/smtp-smuggling.zeek",
        scripts / "smtp-smuggling.zeek",
    )
    result = subprocess.run(
        [
            "podman", "run", "--rm",
            "--security-opt", "seccomp=unconfined",
            "-v", f"{pcaps}:/pcaps:ro",
            "-v", f"{scripts}:/scripts:ro",
            "-v", f"{work}:/work:rw",
            "-w", "/work",
            ZEEK_IMAGE,
            "zeek", "-C", "-r", f"/pcaps/{pcap_path.name}",
            "/scripts/smtp-smuggling.zeek",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        return f"__ZEEK_ERROR__: {result.stderr}"
    notice_log = work / "notice.log"
    return notice_log.read_text() if notice_log.exists() else ""


def _connectivity_smoke() -> bool:
    """Plain EHLO/QUIT against postfix-sender:2525. Proves the lab is
    reachable before we try running any real cases. No carrier, no
    DATA, no smuggling — just protocol handshake."""
    import socket
    try:
        with socket.create_connection(("127.0.0.1", 2525), timeout=5) as s:
            banner = s.recv(4096)
            if not banner.startswith(b"220"):
                return False
            s.sendall(b"EHLO smoke.labnet.test\r\n")
            resp = s.recv(4096)
            if not resp.startswith(b"250"):
                return False
            s.sendall(b"QUIT\r\n")
            bye = s.recv(4096)
            return bye.startswith(b"221")
    except Exception:
        return False


async def main() -> int:
    failures: list[str] = []
    results: list[CaseResult] = []

    # Step 1: connectivity smoke
    print("=== connectivity smoke (EHLO/QUIT against 127.0.0.1:2525) ===")
    if not _connectivity_smoke():
        failures.append("connectivity smoke failed — is podman-compose up?")
        print("FAIL")
        return 1
    print("OK")

    # Step 2: attack payloads
    payloads = {p.id: p for p in load_payloads("payloads/payloads.yaml")}
    for pid in sorted(payloads.keys()):
        print(f"\n=== {pid} ===")
        r = await run_case(pid.lower(), payloads[pid])
        results.append(r)
        print(json.dumps(r.__dict__, indent=2))

    # M0 requires AT LEAST ONE attack to classify as vulnerable.
    vulnerable_ids = [r.payload_id for r in results if r.classification == "vulnerable"]
    if not vulnerable_ids:
        failures.append(
            f"no attack payload classified vulnerable; got: "
            f"{[(r.payload_id, r.classification) for r in results]}"
        )

    # Step 3: Zeek on every vulnerable pcap
    for r in results:
        if r.classification == "vulnerable":
            log = _run_zeek_on_pcap(Path(r.wire_pcap_path))
            if "Parser_Differential_Pattern" not in log:
                failures.append(
                    f"Zeek did not raise notice for {r.case_id}: log={log[:200]}"
                )

    print()
    if failures:
        print("=== M0 FAILED ===")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("=== M0 PASSED ===")
    print("  connectivity: OK")
    for r in results:
        print(
            f"  {r.payload_id}: {r.classification} "
            f"(stub={r.stub_event_count}, maildir={r.maildir_file_count})"
        )
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
