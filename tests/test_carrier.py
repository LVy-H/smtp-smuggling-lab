"""Carrier template tests. Ensure the payload bytes splice in without
mutation and the overall message is a valid RFC 5322-ish envelope."""
from harness.carrier import build_carrier


def test_smuggled_block_bytes_are_preserved_exactly():
    payload = b"\n.\n"
    msg = build_carrier(
        envelope_from="alice@labnet.test",
        envelope_to="bob@labnet.test",
        smuggled_block=payload,
    )
    assert payload in msg
    assert isinstance(msg, bytes)


def test_carrier_has_required_headers():
    msg = build_carrier(
        envelope_from="alice@labnet.test",
        envelope_to="bob@labnet.test",
        smuggled_block=b"",
    )
    assert b"From: alice@labnet.test\r\n" in msg
    assert b"To: bob@labnet.test\r\n" in msg
    assert b"Subject: " in msg
    assert b"Message-ID: " in msg
    assert b"MIME-Version: 1.0\r\n" in msg


def test_carrier_uses_crlf_line_endings_only():
    # Outside the smuggled block, every newline must be CRLF so Postfix
    # doesn't reject the envelope for bare LF before the attack even runs.
    msg = build_carrier(
        envelope_from="alice@labnet.test",
        envelope_to="bob@labnet.test",
        smuggled_block=b"",  # empty smuggled block
    )
    # Count lone LFs that are not preceded by CR
    lone_lfs = 0
    for i, byte in enumerate(msg):
        if byte == 0x0A and (i == 0 or msg[i - 1] != 0x0D):
            lone_lfs += 1
    assert lone_lfs == 0, f"Found {lone_lfs} lone LFs in envelope"


def test_null_byte_in_smuggled_block_preserved():
    payload = b"\x00\r\n.\r\n"
    msg = build_carrier(
        envelope_from="alice@labnet.test",
        envelope_to="bob@labnet.test",
        smuggled_block=payload,
    )
    assert b"\x00" in msg
    assert payload in msg
