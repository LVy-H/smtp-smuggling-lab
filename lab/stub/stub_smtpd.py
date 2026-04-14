"""Stub SMTP receiver — the scientific oracle.

Speaks SMTP correctly per RFC 5321 with exactly one intentional property:
the DATA phase terminator is *strictly* b'\\r\\n.\\r\\n', with no
tolerance for bare-LF or bare-CR variants. This is the whole point:
we are measuring how many discrete MAIL FROM -> DATA -> END cycles the
raw byte stream encodes according to a rigorous parser. Every receiver
in the paper that is vulnerable is *more permissive* than this stub,
which means any smuggling cell where the lab MTA accepts and the stub
agrees that N>1 is a ground-truth positive.

Every discrete DATA completion is logged as one JSON event line to
events_path. The caller reads events_path to get the count.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path


_DATA_TERMINATOR = b"\r\n.\r\n"


@dataclass
class _Session:
    mail_from: str | None = None
    rcpt_tos: list[str] = field(default_factory=list)
    in_data: bool = False
    data_buffer: bytearray = field(default_factory=bytearray)


class StubSmtpd:
    def __init__(self, bind_host: str, bind_port: int, events_path: Path):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.events_path = Path(events_path)
        self.events_path.parent.mkdir(parents=True, exist_ok=True)
        self.events_path.write_text("")
        self._server: asyncio.base_events.Server | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, self.bind_host, self.bind_port
        )

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    def _log(self, event: dict) -> None:
        with self.events_path.open("a") as f:
            f.write(json.dumps(event) + "\n")

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        session = _Session()
        writer.write(b"220 stub.labnet.test ESMTP\r\n")
        await writer.drain()
        try:
            # We read byte-by-byte so the DATA-phase terminator check is
            # byte-exact across buffer boundaries.
            buf = bytearray()
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                buf.extend(chunk)
                # Process as many complete command lines or DATA body as available
                while True:
                    if session.in_data:
                        # Look for the strict CRLF . CRLF terminator
                        idx = buf.find(_DATA_TERMINATOR)
                        if idx == -1:
                            break  # need more bytes
                        # Everything up to and including the terminator
                        # is the DATA body.
                        session.data_buffer.extend(buf[:idx])
                        del buf[: idx + len(_DATA_TERMINATOR)]
                        self._log({
                            "type": "data_complete",
                            "mail_from": session.mail_from,
                            "rcpt_tos": list(session.rcpt_tos),
                            "body_len": len(session.data_buffer),
                        })
                        writer.write(b"250 2.0.0 Ok queued\r\n")
                        await writer.drain()
                        session = _Session()  # reset for next transaction on same conn
                    else:
                        # Command mode — look for a single CRLF line
                        idx = buf.find(b"\r\n")
                        if idx == -1:
                            break
                        line = bytes(buf[:idx])
                        del buf[: idx + 2]
                        await self._handle_command(line, session, writer)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_command(
        self,
        line: bytes,
        session: _Session,
        writer: asyncio.StreamWriter,
    ) -> None:
        upper = line.upper()
        if upper.startswith(b"EHLO") or upper.startswith(b"HELO"):
            writer.write(b"250 stub.labnet.test\r\n")
        elif upper.startswith(b"MAIL FROM:"):
            session.mail_from = line[len(b"MAIL FROM:"):].decode("ascii", errors="replace").strip()
            session.rcpt_tos = []
            self._log({"type": "mail_from", "value": session.mail_from})
            writer.write(b"250 2.1.0 Ok\r\n")
        elif upper.startswith(b"RCPT TO:"):
            rcpt = line[len(b"RCPT TO:"):].decode("ascii", errors="replace").strip()
            session.rcpt_tos.append(rcpt)
            self._log({"type": "rcpt_to", "value": rcpt})
            writer.write(b"250 2.1.5 Ok\r\n")
        elif upper == b"DATA":
            session.in_data = True
            session.data_buffer = bytearray()
            writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
        elif upper == b"RSET":
            session.mail_from = None
            session.rcpt_tos = []
            writer.write(b"250 2.0.0 Ok\r\n")
        elif upper == b"NOOP":
            writer.write(b"250 2.0.0 Ok\r\n")
        elif upper == b"QUIT":
            writer.write(b"221 2.0.0 Bye\r\n")
        else:
            writer.write(b"500 5.5.2 Command not recognized\r\n")
        await writer.drain()
