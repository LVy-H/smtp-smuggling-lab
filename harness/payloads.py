"""Payload loader. Reads payloads/payloads.yaml and returns Payload
dataclasses with raw_bytes already base64-decoded. Decoding happens
exactly once, at load time, so every downstream consumer gets identical
bytes."""
from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml


@dataclass(frozen=True)
class Payload:
    id: str
    raw_bytes: bytes
    family: str
    paper_ref: str
    scope: str
    expected_stub_events: Optional[int] = None
    smuggled_sender: Optional[str] = None
    smuggled_subject: Optional[str] = None
    description: Optional[str] = None


def load_payloads(path: str | Path) -> list[Payload]:
    data = yaml.safe_load(Path(path).read_text())
    out: list[Payload] = []
    for entry in data:
        raw = base64.b64decode(entry["bytes_b64"])
        out.append(
            Payload(
                id=entry["id"],
                raw_bytes=raw,
                family=entry["family"],
                paper_ref=entry["paper_ref"],
                scope=entry["scope"],
                expected_stub_events=entry.get("expected_stub_events"),
                smuggled_sender=entry.get("smuggled_sender"),
                smuggled_subject=entry.get("smuggled_subject"),
                description=entry.get("description"),
            )
        )
    return out
