"""Log-parser contrast detector. Reads Postfix mail.log or Exim
mainlog and flags SMTP smuggling as a secondary symptom — multiple
queue IDs from one client session, or multiple mail receipts from
the same client within a short window.

This detector is expected to miss many cases Zeek catches. That
gap is the finding; don't hide it."""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


# Postfix queue-ID line:
#   Apr 14 12:21:08 sender postfix/smtpd[383]: D1132842816: client=unknown[10.89.2.20]
_POSTFIX_CLIENT_RX = re.compile(
    r"postfix/smtpd\[\d+\]:\s+([A-Fa-f0-9]+):\s+client=\S+\[(\d+\.\d+\.\d+\.\d+)\]"
)

# Exim received-mail line:
#   2026-04-14 12:21:08 1abcde-000001-XY <= alice@labnet.test H=sender [10.89.2.20] ...
_EXIM_RECEIVE_RX = re.compile(
    r"(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}).*?<=\s+(\S+)\s+H=\S+\s+\[(\d+\.\d+\.\d+\.\d+)\]"
)


def parse_postfix_log(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    for line in path.read_text(errors="replace").splitlines():
        m = _POSTFIX_CLIENT_RX.search(line)
        if m:
            rows.append({"queue_id": m.group(1), "client_ip": m.group(2)})
    return rows


def parse_exim_log(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    for line in path.read_text(errors="replace").splitlines():
        m = _EXIM_RECEIVE_RX.search(line)
        if m:
            rows.append({
                "timestamp": m.group(1),
                "sender": m.group(2),
                "client_ip": m.group(3),
            })
    return rows


def detect_multi_queue_from_one_client(postfix_rows: list[dict]) -> list[dict]:
    """Return notices when the same client_ip produces multiple queue
    IDs. This catches the downstream symptom of a successful smuggling."""
    by_client: dict[str, list[str]] = defaultdict(list)
    for row in postfix_rows:
        by_client[row["client_ip"]].append(row["queue_id"])

    notices: list[dict] = []
    for client_ip, qids in by_client.items():
        if len(qids) >= 2:
            notices.append({
                "type": "multi-queue-per-client",
                "client_ip": client_ip,
                "queue_ids": qids,
                "count": len(qids),
            })
    return notices


def detect_for_pcap_case(log_dir: Path) -> list[dict]:
    """Run all detectors against a directory containing mail.log and/or
    mainlog and return a merged notice list."""
    notices: list[dict] = []

    pf_log = log_dir / "mail.log"
    if pf_log.exists():
        rows = parse_postfix_log(pf_log)
        notices.extend(detect_multi_queue_from_one_client(rows))

    ex_log = log_dir / "mainlog"
    if ex_log.exists():
        rows = parse_exim_log(ex_log)
        by_client: dict[str, int] = defaultdict(int)
        for r in rows:
            by_client[r["client_ip"]] += 1
        for ip, cnt in by_client.items():
            if cnt >= 2:
                notices.append({
                    "type": "exim-multi-receive",
                    "client_ip": ip,
                    "count": cnt,
                })

    return notices


if __name__ == "__main__":
    target = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    for n in detect_for_pcap_case(target):
        print(json.dumps(n))
