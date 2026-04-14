"""Matrix runner. Brings up each profile in turn, runs every payload
against the active pairing, and writes results/matrix.json plus
results/log-parser-notices.json."""
from __future__ import annotations

import asyncio
import dataclasses
import json
import subprocess
import sys
import time
from pathlib import Path

from harness.payloads import load_payloads
from harness.run_case import CaseResult, run_case


PAIRS = ("p2p", "p2e", "e2p", "e2e")
COMPOSE_FILE = "lab/podman-compose.yml"
RESULTS_DIR = Path("results")


def _compose(cmd: list[str], profile: str) -> None:
    subprocess.run(
        ["podman-compose", "-f", COMPOSE_FILE, "--profile", profile, *cmd],
        check=True,
    )


def _compose_up(profile: str) -> None:
    _compose(["up", "-d"], profile)
    time.sleep(6)


def _compose_down(profile: str) -> None:
    try:
        _compose(["down"], profile)
    except subprocess.CalledProcessError:
        pass


_SENDER_CONTAINER_BY_PAIR = {
    "p2p": "postfix-sender", "p2e": "postfix-sender",
    "e2p": "exim-sender",    "e2e": "exim-sender",
}


def _dump_sender_log(case_id: str, pair: str) -> dict:
    """Dump the sender's mail log to results/logs/<case_id>/ and run
    the log parser. Returns a list of notices."""
    case_log_dir = RESULTS_DIR / "logs" / case_id
    case_log_dir.mkdir(parents=True, exist_ok=True)
    sender_container = _SENDER_CONTAINER_BY_PAIR[pair]

    if sender_container.startswith("postfix"):
        log_path = case_log_dir / "mail.log"
        with open(log_path, "w") as f:
            subprocess.run(
                ["podman", "exec", sender_container, "cat", "/var/log/mail.log"],
                stdout=f, check=False,
            )
    else:
        log_path = case_log_dir / "mainlog"
        with open(log_path, "w") as f:
            subprocess.run(
                ["podman", "exec", sender_container, "cat", "/var/spool/exim4/log/mainlog"],
                stdout=f, check=False,
            )

    from detect.logs.parse_mail_log import detect_for_pcap_case
    notices = detect_for_pcap_case(case_log_dir)
    return notices


async def main() -> int:
    payloads = sorted(load_payloads("payloads/payloads.yaml"), key=lambda p: p.id)
    all_results: list[CaseResult] = []
    log_parser_notices: dict[str, list[dict]] = {}

    for pair in PAIRS:
        print(f"\n\n====================== pair={pair} ======================")
        _compose_down(pair)
        _compose_up(pair)
        try:
            for payload in payloads:
                case_id = f"{pair}-{payload.id.lower()}"
                print(f"\n--- {case_id} ---")
                r = await run_case(case_id=case_id, payload=payload, pair=pair)
                print(json.dumps(dataclasses.asdict(r), indent=2))
                all_results.append(r)
                log_parser_notices[case_id] = _dump_sender_log(case_id, pair)
        finally:
            _compose_down(pair)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    matrix_path = RESULTS_DIR / "matrix.json"
    matrix_path.write_text(json.dumps(
        [dataclasses.asdict(r) for r in all_results],
        indent=2,
    ))

    notices_path = RESULTS_DIR / "log-parser-notices.json"
    notices_path.write_text(json.dumps(log_parser_notices, indent=2))

    print(f"\nWrote {matrix_path} ({len(all_results)} cells)")
    print(f"Wrote {notices_path}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
