#!/bin/bash
set -euo pipefail

ROLE="${EXIM_ROLE:-receiver}"

if [ "$ROLE" = "sender" ]; then
    TARGET="${TARGET_RECEIVER:-postfix-receiver}"
    sed -i 's/^primary_hostname = .*/primary_hostname = exim-sender.labnet.test/' /etc/exim4/exim4.conf
    # Drop labnet.test entries from local_domains so bob@labnet.test
    # routes remotely instead of being delivered to sender's own Maildir.
    sed -i 's/^domainlist local_domains = .*/domainlist local_domains = @ : localhost/' /etc/exim4/exim4.conf
    TARGET="$TARGET" python3 - <<'PYEOF'
import os
from pathlib import Path
target = os.environ["TARGET"]
p = Path("/etc/exim4/exim4.conf")
text = p.read_text()
smarthost_block = f"""\
send_via_smarthost:
  driver = manualroute
  domains = ! +local_domains
  route_list = * {target} byname
  transport = remote_smtp
  self = send

"""
marker = "begin routers\n"
idx = text.find(marker) + len(marker)
text = text[:idx] + "\n" + smarthost_block + text[idx:]
p.write_text(text)
PYEOF
elif [ "$ROLE" = "receiver" ]; then
    sed -i 's/^primary_hostname = .*/primary_hostname = exim-receiver.labnet.test/' /etc/exim4/exim4.conf
fi

# Make Exim log to /var/log/exim4/ where we expect to find it.
mkdir -p /var/log/exim4
chown Debian-exim:Debian-exim /var/log/exim4
if ! grep -q '^log_file_path' /etc/exim4/exim4.conf; then
    sed -i '1i log_file_path = /var/log/exim4/%slog' /etc/exim4/exim4.conf
fi

install -d -o bob -g bob -m 0700 \
    /home/bob/Maildir \
    /home/bob/Maildir/new \
    /home/bob/Maildir/cur \
    /home/bob/Maildir/tmp

exec exim4 -bdf -v -q30m
