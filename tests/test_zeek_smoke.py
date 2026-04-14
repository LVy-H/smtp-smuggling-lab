"""Zeek detector smoke test. Runs Zeek (via the containerized image)
against committed pcap fixtures and asserts:

  - On a vulnerable pcap (case-a1 or case-a5 from results/), Zeek
    raises at least one Parser_Differential_Pattern notice.

  - On the baseline pcap (case-baseline with empty smuggled_block),
    Zeek raises zero notices.

Requires podman on the host and the zeek/zeek:lts image pulled. If
podman is missing the test is skipped rather than failed (so CI on
dev machines without podman still gets signal from other tests)."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
ZEEK_IMAGE = "docker.io/zeek/zeek:lts"


def _run_zeek(pcap_path: Path, work_dir: Path) -> str:
    """Run Zeek on a pcap via podman container. Returns the notice.log
    contents (empty string if no notice.log was produced)."""
    # Zeek in user namespace can't statfs /run/host/mnt, so stage files in /tmp
    stage = Path("/tmp/m0-zeek-pytest")
    pcaps = stage / "pcaps"
    scripts = stage / "scripts"
    work = stage / "work"
    for d in (pcaps, scripts, work):
        d.mkdir(parents=True, exist_ok=True)
    shutil.copy(pcap_path, pcaps / pcap_path.name)
    shutil.copy(REPO / "detect/gateway/smtp-smuggling.zeek", scripts / "smtp-smuggling.zeek")
    for old in work.iterdir():
        old.unlink()

    result = subprocess.run(
        [
            "podman", "run", "--rm",
            "--security-opt", "seccomp=unconfined",
            "-v", f"{pcaps}:/pcaps:ro",
            "-v", f"{scripts}:/scripts:ro",
            "-v", f"{work}:/work:rw",
            "-w", "/work",
            ZEEK_IMAGE,
            "zeek", "-C", "-r", f"/pcaps/{pcap_path.name}", "/scripts/smtp-smuggling.zeek",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"zeek failed: {result.stderr}"

    notice_log = work / "notice.log"
    return notice_log.read_text() if notice_log.exists() else ""


def _podman_available() -> bool:
    return shutil.which("podman") is not None


@pytest.mark.skipif(not _podman_available(), reason="podman not installed")
def test_zeek_raises_notice_on_vulnerable_case_a1():
    pcap = REPO / "results/pcaps/case-a1.pcap"
    if not pcap.exists():
        pytest.skip(f"{pcap} not present (run harness.run_case first)")
    log = _run_zeek(pcap, Path("/tmp/m0-zeek-pytest/work"))
    assert "Parser_Differential_Pattern" in log, f"expected notice, got:\n{log}"


@pytest.mark.skipif(not _podman_available(), reason="podman not installed")
def test_zeek_raises_notice_on_vulnerable_case_a5():
    pcap = REPO / "results/pcaps/case-a5.pcap"
    if not pcap.exists():
        pytest.skip(f"{pcap} not present (run harness.run_case first)")
    log = _run_zeek(pcap, Path("/tmp/m0-zeek-pytest/work"))
    assert "Parser_Differential_Pattern" in log, f"expected notice, got:\n{log}"


@pytest.mark.skipif(not _podman_available(), reason="podman not installed")
def test_zeek_silent_on_baseline_case():
    pcap = REPO / "results/pcaps/case-baseline.pcap"
    if not pcap.exists():
        pytest.skip(f"{pcap} not present (run harness.run_case with empty payload first)")
    log = _run_zeek(pcap, Path("/tmp/m0-zeek-pytest/work"))
    assert "Parser_Differential_Pattern" not in log, f"unexpected notice on baseline:\n{log}"
