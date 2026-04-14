"""Raw-socket SMTP client for the lab harness.

Does not use stdlib `smtplib`: that module normalizes line endings
(b'\\n' -> b'\\r\\n') and strips NUL bytes, which destroys the exact
byte content needed for this research reproduction. Instead we speak
the minimum SMTP subset over a raw socket so every byte the carrier
builder emits lands on the wire unchanged.
"""
from __future__ import annotations

import socket
import time

from harness.carrier import build_carrier
from harness.payloads import Payload


def _read_response(sock: socket.socket, timeout: float = 5.0) -> bytes:
    """Read one SMTP response (possibly multi-line).

    Per RFC 5321 a multi-line reply uses '-' as the 4th character on
    continuation lines and ' ' (space) on the final line. We read
    until we see the terminating space-marker line.
    """
    sock.settimeout(timeout)
    buf = bytearray()
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
        lines = bytes(buf).split(b"\r\n")
        if len(lines) >= 2 and len(lines[-2]) >= 4 and lines[-2][3:4] == b" ":
            break
    return bytes(buf)


def _expect_code(resp: bytes, code: bytes) -> None:
    if not resp.startswith(code):
        raise RuntimeError(f"expected {code!r}, got {resp!r}")


def send_case(
    host: str,
    port: int,
    envelope_from: str,
    envelope_to: str,
    payload: Payload,
    timeout: float = 10.0,
) -> None:
    """Send one carrier email containing one spliced payload block
    through a real SMTP endpoint via raw socket. Blocks until QUIT
    is acknowledged.

    The payload bytes are spliced verbatim into the carrier body;
    `sendall` writes exactly what the carrier builder produced.
    """
    carrier = build_carrier(
        envelope_from=envelope_from,
        envelope_to=envelope_to,
        smuggled_block=payload.raw_bytes,
    )

    with socket.create_connection((host, port), timeout=timeout) as sock:
        _expect_code(_read_response(sock), b"220")
        sock.sendall(b"EHLO harness.labnet.test\r\n")
        _expect_code(_read_response(sock), b"250")
        sock.sendall(f"MAIL FROM:<{envelope_from}>\r\n".encode("ascii"))
        _expect_code(_read_response(sock), b"250")
        sock.sendall(f"RCPT TO:<{envelope_to}>\r\n".encode("ascii"))
        _expect_code(_read_response(sock), b"250")
        sock.sendall(b"DATA\r\n")
        _expect_code(_read_response(sock), b"354")
        sock.sendall(carrier)
        _expect_code(_read_response(sock), b"250")
        sock.sendall(b"QUIT\r\n")
        _expect_code(_read_response(sock), b"221")
    time.sleep(0.05)
