"""Build a minimal pcap containing one SMTP session with a bare-LF
dot smuggling attempt embedded in the DATA body. Used as a
deterministic fixture for the Zeek smoke test."""
from __future__ import annotations

import sys
from pathlib import Path

import dpkt


def build(output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    f = open(output_path, "wb")
    writer = dpkt.pcap.Writer(f)

    def pkt(sport: int, dport: int, payload: bytes, seq: int) -> bytes:
        tcp = dpkt.tcp.TCP(
            sport=sport, dport=dport,
            seq=seq, ack=1,
            flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH,
            off_x2=0x50,
        )
        tcp.data = payload
        ip = dpkt.ip.IP(
            src=bytes([10, 0, 0, 1]),
            dst=bytes([10, 0, 0, 2]),
            p=dpkt.ip.IP_PROTO_TCP,
        )
        ip.data = tcp
        ip.len = 20 + 20 + len(payload)
        eth = dpkt.ethernet.Ethernet(
            src=b"\x00\x00\x00\x00\x00\x01",
            dst=b"\x00\x00\x00\x00\x00\x02",
            type=dpkt.ethernet.ETH_TYPE_IP,
        )
        eth.data = ip
        return bytes(eth)

    commands = [
        b"EHLO smoke.test\r\n",
        b"MAIL FROM:<a@a.test>\r\n",
        b"RCPT TO:<b@b.test>\r\n",
        b"DATA\r\n",
        b"Subject: smoke\r\n\r\nbody text\n.\nMAIL FROM:<evil@evil.test>\r\n",
        b".\r\n",
        b"QUIT\r\n",
    ]
    seq = 1
    for payload in commands:
        writer.writepkt(pkt(40000, 25, payload, seq))
        seq += len(payload)

    writer.close()
    f.close()


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/smoke-bare-lf.pcap")
    build(out)
    print(f"wrote {out}")
