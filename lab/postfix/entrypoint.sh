#!/bin/bash
set -euo pipefail

ROLE="${POSTFIX_ROLE:-receiver}"

if [ "$ROLE" = "sender" ]; then
    postconf -e 'mydestination = $myhostname, localhost'
    postconf -e 'relayhost = [postfix-receiver]:25'
    postconf -e 'smtp_host_lookup = native'
    postconf -e 'disable_dns_lookups = yes'
elif [ "$ROLE" = "receiver" ]; then
    postconf -e 'mydestination = labnet.test, receiver.labnet.test, localhost'
fi

postfix set-permissions >/dev/null 2>&1 || true
postfix check

rsyslogd

postfix start-fg &
POSTFIX_PID=$!
touch /var/log/mail.log
tail -F /var/log/mail.log &
TAIL_PID=$!

trap "kill $POSTFIX_PID $TAIL_PID 2>/dev/null || true" TERM INT EXIT
wait $POSTFIX_PID
