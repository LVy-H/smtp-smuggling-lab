"""Payload loader byte-preservation tests. These catch line-ending
normalization bugs before they silently corrupt the whole matrix."""
from harness.payloads import Payload, load_payloads


def test_a1_decodes_to_exact_lf_dot_lf():
    payloads = {p.id: p for p in load_payloads("payloads/payloads.yaml")}
    assert payloads["A1"].raw_bytes == b"\n.\n"
    assert payloads["A1"].family == "bare-lf"
    assert payloads["A1"].smuggled_sender == "attacker@evil.test"


def test_a5_decodes_to_exact_crlf_dot_lf():
    payloads = {p.id: p for p in load_payloads("payloads/payloads.yaml")}
    assert payloads["A5"].raw_bytes == b"\r\n.\n"
    assert payloads["A5"].family == "crlf-dot-lf"


def test_all_payloads_are_scope_lab():
    for p in load_payloads("payloads/payloads.yaml"):
        assert p.scope == "lab"


def test_payload_raw_bytes_is_bytes_not_str():
    for p in load_payloads("payloads/payloads.yaml"):
        assert isinstance(p.raw_bytes, bytes), f"{p.id} is {type(p.raw_bytes)}"


def test_two_payloads_in_m0_set():
    payloads = load_payloads("payloads/payloads.yaml")
    assert len(payloads) == 2
    assert {p.id for p in payloads} == {"A1", "A5"}
