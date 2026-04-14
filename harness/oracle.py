"""Pcap-to-stub oracle.

Reads a pcap captured on labnet, reassembles the client -> server TCP
payload for the SMTP port, and replays those raw bytes to the stub SMTP
receiver. The stub's data_complete event count is the scientific
ground truth for 'how many emails did this byte stream encode?'
"""
from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path

import dpkt


def extract_smtp_data_bytes(pcap_path: Path, server_port: int = 25) -> bytes:
    """Concatenate all TCP payloads from packets destined to `server_port`
    in capture order. This is simple in-order concatenation (not full TCP
    reassembly) — sufficient for lab captures where packets arrive in
    order and without loss.
    """
    buf = bytearray()
    with open(pcap_path, "rb") as f:
        for _ts, pkt in dpkt.pcap.Reader(f):
            try:
                eth = dpkt.ethernet.Ethernet(pkt)
            except Exception:
                continue
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            if tcp.dport != server_port:
                continue
            if tcp.data:
                buf.extend(tcp.data)
    return bytes(buf)


async def replay_against_stub(
    pcap_path: Path,
    stub_host: str = "127.0.0.1",
    stub_port: int = 3560,
) -> None:
    """Replay the client->server SMTP bytes from `pcap_path` against
    a running stub. The caller must then read the stub's events_path
    with count_data_complete_events to get the actual count.
    """
    raw = extract_smtp_data_bytes(pcap_path)

    def _send() -> None:
        with socket.create_connection((stub_host, stub_port), timeout=10) as sock:
            sock.sendall(raw)
            sock.shutdown(socket.SHUT_WR)
            try:
                while sock.recv(4096):
                    pass
            except socket.timeout:
                pass

    await asyncio.to_thread(_send)
    await asyncio.sleep(0.2)


def count_data_complete_events(events_path: Path) -> int:
    """Parse the stub's jsonl event log and count data_complete events."""
    if not events_path.exists():
        return 0
    count = 0
    for line in events_path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            continue
        if evt.get("type") == "data_complete":
            count += 1
    return count
