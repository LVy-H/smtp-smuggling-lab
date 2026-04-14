#!/bin/sh
set -e

PCAP_DIR="${PCAP_DIR:-/pcaps}"
IFACE="${IFACE:-eth0}"
FILTER="${FILTER:-port 25}"

mkdir -p "$PCAP_DIR"

CURRENT=""
TCPDUMP_PID=""
while true; do
    if [ -f "$PCAP_DIR/current-case.txt" ]; then
        NEW=$(cat "$PCAP_DIR/current-case.txt")
        if [ "$NEW" != "$CURRENT" ]; then
            if [ -n "$TCPDUMP_PID" ]; then
                kill "$TCPDUMP_PID" 2>/dev/null || true
                wait "$TCPDUMP_PID" 2>/dev/null || true
            fi
            CURRENT="$NEW"
            tcpdump -i "$IFACE" -s 0 -U -w "$PCAP_DIR/case-${CURRENT}.pcap" "$FILTER" &
            TCPDUMP_PID=$!
        fi
    fi
    sleep 0.2
done
