# SMTP smuggling PoC

Minimal demo of the parser-differential bug from Wang et al., USENIX
Security '25 (Table 1, payload A1: bare-LF dot bare-LF, `b"\n.\n"`).

## Files

- `poc_smuggle.py` — the entire PoC, ~30 lines, stdlib only
- `poc_smuggle.pcap` — wire capture of one PoC run, open with Wireshark

## Requirements

- Python 3 (stdlib only, no dependencies)
- A Postfix sender MTA listening on `127.0.0.1:2525` with
  `smtpd_forbid_bare_newline = no` (the Postfix default before 3.9),
  configured to relay outbound mail to a downstream receiver
- The downstream receiver must accept mail for `bob@labnet.test`

The lab in this repo (`lab/podman-compose.yml`, `p2p` profile) provides
exactly that environment using two isolated Podman containers.

## Run

With the lab running:

```
python3 demo/poc_smuggle.py
```

The harness sends **one** SMTP transaction. The receiver delivers
**two** messages to `bob`'s mailbox: the legitimate carrier and a
smuggled message whose `From:` header is a spoofed sender:

```
$ podman exec postfix-receiver ls /home/bob/Maildir/new
1776184325.V10302I842c36M925037.receiver.labnet.test    # carrier
1776184325.V10302I842c3bM927044.receiver.labnet.test    # smuggled

# carrier:
From: hoang@uit.test
To: long@labnet.test
Subject: hello

# smuggled:
From: thaykhoa@labnet.test
To: bob@labnet.test
Subject: SMUGGLED
```

## What to look for in `poc_smuggle.pcap`

Open the capture in Wireshark, right-click any packet on TCP/25, choose
**Follow → TCP Stream**. You will see *two* SMTP sessions on the wire
between `postfix-sender` and `postfix-receiver`, even though the harness
only ran one transaction against `postfix-sender`:

```
EHLO sender.labnet.test
MAIL FROM:<alice@labnet.test>
RCPT TO:<bob@labnet.test>
DATA
... carrier body ...
hello
.
QUIT
EHLO sender.labnet.test
MAIL FROM:<thaykhoa@labnet.test>      <-- smuggled envelope
RCPT TO:<bob@labnet.test>             <-- local recipient
DATA
... smuggled body ...
-1
.
QUIT
```

`postfix-sender`'s parser treated the bare-LF dot bare-LF (`b"\n.\n"`)
as end-of-message, then re-emitted **two** clean RFC-conformant SMTP
transactions to `postfix-receiver`. Both inherit the upstream's
authentication.

## Why this is dangerous in production

Modern MTAs do **not** relay arbitrary mail by default — a public MX
will reject any `RCPT TO:<remote-domain>` with `554 5.7.1 Relay access
denied` unless the client authenticates. So the attack vector is **not**
"trick the receiver into relaying somewhere external."

The realistic threat model is a two-MTA chain where the attacker
authenticates legitimately with the **upstream** MTA and the receiver
is **authoritative** for the victim's domain:

```
attacker --auth--> upstream MTA  --SMTP-->  victim MX  --local--> bob@victim.com
                   (SaaS / ISP)             (authoritative for victim.com)
```

The smuggled mail's `RCPT TO` targets a recipient the victim MX is
already local for, so relay restrictions don't apply. SPF passes
because the bytes arrive from the upstream's allowlisted IP. DKIM
passes because the wrapper transmission is signed by the upstream.
DMARC passes because both align. The smuggled mail lands in bob's
mailbox under a spoofed `From:` header.

This PoC reproduces exactly that local-delivery shape: the smuggled
`RCPT TO:<bob@labnet.test>` is a recipient the lab receiver is
authoritative for, and the smuggled mail is delivered silently
alongside the carrier.
