#!/bin/bash
set -euo pipefail

ROLE="${EXIM_ROLE:-receiver}"

if [ "$ROLE" = "sender" ]; then
    sed -i 's/^primary_hostname = .*/primary_hostname = exim-sender.labnet.test/' /etc/exim4/exim4.conf
    python3 - <<'PYEOF'
from pathlib import Path
p = Path("/etc/exim4/exim4.conf")
text = p.read_text()
smarthost_block = """\
send_via_postfix_receiver:
  driver = manualroute
  domains = ! +local_domains
  route_list = * postfix-receiver byname
  transport = remote_smtp

send_via_exim_receiver:
  driver = manualroute
  domains = ! +local_domains
  route_list = * exim-receiver byname
  transport = remote_smtp

"""
marker = "begin routers\n"
idx = text.find(marker) + len(marker)
text = text[:idx] + "\n" + smarthost_block + text[idx:]
p.write_text(text)
PYEOF
elif [ "$ROLE" = "receiver" ]; then
    sed -i 's/^primary_hostname = .*/primary_hostname = exim-receiver.labnet.test/' /etc/exim4/exim4.conf
fi

install -d -o bob -g bob -m 0700 \
    /home/bob/Maildir \
    /home/bob/Maildir/new \
    /home/bob/Maildir/cur \
    /home/bob/Maildir/tmp

exec exim4 -bdf -v -q30m
