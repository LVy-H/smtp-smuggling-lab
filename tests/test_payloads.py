"""Payload loader byte-preservation tests. These catch line-ending
normalization bugs before they silently corrupt the whole matrix."""
from harness.payloads import Payload, load_payloads


_EXPECTED_BYTES = {
    "A1":  b"\n.\n",
    "A2":  b"\n.\r\n",
    "A3":  b"\r.\r",
    "A4":  b"\r.\r\n",
    "A5":  b"\r\n.\n",
    "A6":  b"\r\n.\r",
    "A7":  b"\x00\r\n.\r\n",
    "A8":  b"\r\n\x00.\r\n",
    "A9":  b"\r\x00\n.\r\n",
    "A10": b"\x00\r\n.\r\n",
    "A11": b"\r\n.\x00\r\n",
    "A12": b"\r\n.\r\x00\n",
    "A13": b"\r\n.\r\n\x00",
}


def test_payload_count_matches_paper_table_1():
    payloads = load_payloads("payloads/payloads.yaml")
    assert len(payloads) == 13
    assert {p.id for p in payloads} == set(_EXPECTED_BYTES.keys())


def test_every_payload_decodes_to_exact_expected_bytes():
    payloads = {p.id: p for p in load_payloads("payloads/payloads.yaml")}
    for pid, expected in _EXPECTED_BYTES.items():
        actual = payloads[pid].raw_bytes
        assert actual == expected, f"{pid}: expected {expected!r}, got {actual!r}"


def test_every_payload_has_smuggled_sender_and_subject():
    for p in load_payloads("payloads/payloads.yaml"):
        assert p.smuggled_sender == "attacker@evil.test"
        assert p.smuggled_subject == f"SMUGGLED-{p.id}"


def test_every_payload_is_scope_lab():
    for p in load_payloads("payloads/payloads.yaml"):
        assert p.scope == "lab"


def test_payload_raw_bytes_is_bytes_not_str():
    for p in load_payloads("payloads/payloads.yaml"):
        assert isinstance(p.raw_bytes, bytes), f"{p.id} is {type(p.raw_bytes)}"
