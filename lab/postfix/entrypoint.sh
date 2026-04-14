#!/bin/bash
set -euo pipefail

ROLE="${POSTFIX_ROLE:-receiver}"

if [ "$ROLE" = "sender" ]; then
    TARGET="${TARGET_RECEIVER:-postfix-receiver}"
    postconf -e 'myhostname = sender.labnet.test'
    postconf -e 'mydestination = sender.labnet.test, localhost'
    postconf -e "relayhost = [${TARGET}]:25"
    postconf -e 'smtp_host_lookup = native'
    postconf -e 'disable_dns_lookups = yes'
elif [ "$ROLE" = "receiver" ]; then
    postconf -e 'myhostname = receiver.labnet.test'
    postconf -e 'mydestination = receiver.labnet.test, labnet.test, localhost'
fi

# Disable chroot on smtp and smtpd services so they can read the
# container's /etc/hosts (Debian defaults to chroot=y, which isolates
# them into /var/spool/postfix with no resolver config).
postconf -F 'smtp/unix/chroot=n'
postconf -F 'smtp/inet/chroot=n'
postconf -F 'relay/unix/chroot=n'
postconf -F 'lmtp/unix/chroot=n'

# Ensure the receiver's Maildir structure exists on the mounted volume.
# podman compose volume mounts clobber the init structure from the image.
install -d -o bob -g bob -m 0700 /home/bob/Maildir /home/bob/Maildir/new /home/bob/Maildir/cur /home/bob/Maildir/tmp

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
