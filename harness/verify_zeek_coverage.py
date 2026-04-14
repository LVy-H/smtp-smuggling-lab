"""Run the Zeek smuggling detector against every sender-side pcap from
the matrix run and check whether each `vulnerable` cell produces at least
one notice. Writes results/zeek-coverage.json.

Coverage is the M1 success criterion for the inline detector: did Zeek
catch every cell that the maildir-oracle classified as vulnerable?
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path


ZEEK_IMAGE = "docker.io/zeek/zeek:lts"
SCRIPT_PATH = Path("detect/gateway/smtp-smuggling.zeek")
MATRIX_PATH = Path("results/matrix.json")
OUT_PATH = Path("results/zeek-coverage.json")
WORK_ROOT = Path("/tmp/zeek-coverage")


def _run_zeek_on(pcap: Path) -> list[dict]:
    """Run Zeek on `pcap` in an isolated /tmp workdir and return parsed
    notice.log rows. Empty list = no notices fired."""
    work = WORK_ROOT / pcap.stem
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    shutil.copy(pcap, work / pcap.name)
    shutil.copy(SCRIPT_PATH, work / SCRIPT_PATH.name)

    subprocess.run(
        ["podman", "run", "--rm",
         "--security-opt", "seccomp=unconfined",
         "-v", f"{work}:/work", "-w", "/work",
         ZEEK_IMAGE,
         "zeek", "-C", "-r", pcap.name, SCRIPT_PATH.name],
        check=False,
        capture_output=True,
    )

    notice_log = work / "notice.log"
    if not notice_log.exists():
        return []

    rows: list[dict] = []
    fields: list[str] = []
    for line in notice_log.read_text().splitlines():
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#") or not line.strip():
            continue
        cols = line.split("\t")
        if len(cols) != len(fields):
            continue
        row = dict(zip(fields, cols))
        if row.get("note", "").startswith("SMTPSmuggling::"):
            rows.append({
                "note": row["note"],
                "msg": row.get("msg", ""),
                "src": row.get("src", ""),
            })
    return rows


def main() -> int:
    matrix = json.loads(MATRIX_PATH.read_text())
    coverage: dict[str, dict] = {}
    missed: list[str] = []
    fired_on_clean: list[str] = []

    for cell in matrix:
        case_id = cell["case_id"]
        pcap = Path(cell["wire_pcap_sender"])
        if not pcap.exists() or pcap.stat().st_size == 0:
            coverage[case_id] = {"notices": [], "skipped": True}
            continue

        notices = _run_zeek_on(pcap)
        coverage[case_id] = {
            "classification": cell["classification"],
            "notice_count": len(notices),
            "notices": notices,
        }

        if cell["classification"] == "vulnerable" and not notices:
            missed.append(case_id)
        if cell["classification"] == "not-vulnerable" and notices:
            fired_on_clean.append(case_id)

        marker = "FIRE" if notices else "miss"
        print(f"  {case_id:14s} ({cell['classification']:18s}) -> {marker} ({len(notices)} notices)")

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps({
        "summary": {
            "total_cells": len(matrix),
            "vulnerable_cells_missed": missed,
            "clean_cells_fired_on": fired_on_clean,
        },
        "per_case": coverage,
    }, indent=2))
    print(f"\nWrote {OUT_PATH}")
    print(f"Vulnerable cells missed by Zeek: {len(missed)}")
    print(f"Non-vulnerable cells fired on:   {len(fired_on_clean)}")
    return 0 if not missed else 1


if __name__ == "__main__":
    sys.exit(main())
