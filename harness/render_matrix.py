"""Render matrix.json as matrix.md for the report."""
from __future__ import annotations

import json
import sys
from pathlib import Path


PAIRS = ("p2p", "p2e", "e2p", "e2e")
PAIR_LABELS = {
    "p2p": "Postfix → Postfix",
    "p2e": "Postfix → Exim",
    "e2p": "Exim → Postfix",
    "e2e": "Exim → Exim",
}
_CLASS_SYMBOL = {
    "vulnerable": "✗",
    "not-vulnerable": "✓",
    "sanitized-or-dropped": "~",
    "rejected-by-receiver": "R",
}


def _payload_sort_key(pid: str) -> tuple[int, int]:
    """Sort A1 < A2 < ... < A13 numerically rather than lex."""
    n = int(pid[1:]) if pid[1:].isdigit() else 999
    return (len(pid), n)


def render(matrix_path: Path, output_path: Path) -> None:
    rows = json.loads(matrix_path.read_text())
    by_payload: dict[str, dict[str, str]] = {}
    for r in rows:
        pid = r["payload_id"]
        pair = r["pair"]
        by_payload.setdefault(pid, {})[pair] = r["classification"]

    header = "| Payload | " + " | ".join(PAIR_LABELS[p] for p in PAIRS) + " |"
    sep = "| --- | " + " | ".join("---" for _ in PAIRS) + " |"

    lines = [
        "# SMTP Smuggling Matrix — M1",
        "",
        "Generated from `results/matrix.json` by `harness/render_matrix.py`.",
        "",
        "Legend: ✗ vulnerable · ✓ not-vulnerable · ~ sanitized-or-dropped · R rejected-by-receiver · ? unknown/missing",
        "",
        header,
        sep,
    ]
    payload_ids = sorted(by_payload.keys(), key=_payload_sort_key)
    for pid in payload_ids:
        cells = by_payload[pid]
        row = f"| **{pid}** | " + " | ".join(
            _CLASS_SYMBOL.get(cells.get(p, "unknown"), "?") for p in PAIRS
        ) + " |"
        lines.append(row)

    output_path.write_text("\n".join(lines) + "\n")
    print(f"wrote {output_path}")


if __name__ == "__main__":
    matrix = Path(sys.argv[1] if len(sys.argv) > 1 else "results/matrix.json")
    output = Path(sys.argv[2] if len(sys.argv) > 2 else "results/matrix.md")
    render(matrix, output)
