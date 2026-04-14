"""Matrix regression test. Compares results/matrix.json against
tests/expected_matrix.json. On first run (empty golden), self-populates
and fails to prompt a re-run."""
import json
from pathlib import Path

import pytest


GOLDEN_PATH = Path("tests/expected_matrix.json")
MATRIX_PATH = Path("results/matrix.json")


@pytest.mark.skipif(not MATRIX_PATH.exists(), reason="run harness.run_matrix first")
def test_matrix_matches_golden_or_populates_empty_golden():
    matrix = json.loads(MATRIX_PATH.read_text())
    golden = json.loads(GOLDEN_PATH.read_text())
    observed = {f"{r['pair']}-{r['payload_id']}": r["classification"] for r in matrix}

    if not golden.get("cells"):
        golden["cells"] = observed
        GOLDEN_PATH.write_text(json.dumps(golden, indent=2, sort_keys=True) + "\n")
        pytest.fail(
            f"golden was empty; populated with {len(observed)} cells. "
            f"Re-run this test to see it pass."
        )

    expected_cells = golden["cells"]
    drift = {
        k: (expected_cells[k], observed[k])
        for k in expected_cells.keys() & observed.keys()
        if expected_cells[k] != observed[k]
    }
    missing = expected_cells.keys() - observed.keys()
    extra = observed.keys() - expected_cells.keys()

    if drift or missing or extra:
        msg = []
        if drift:
            msg.append(f"drift: {drift}")
        if missing:
            msg.append(f"missing from observed: {sorted(missing)}")
        if extra:
            msg.append(f"extra in observed: {sorted(extra)}")
        pytest.fail("; ".join(msg))
