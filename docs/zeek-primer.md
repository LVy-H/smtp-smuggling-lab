# Zeek in Anger — 30-Minute Primer for This Project

Zeek is a network traffic analyzer that reconstructs TCP streams and
runs scripts on the reconstructed byte sequences. In this project it
reads pcap files (not live traffic) and runs
`detect/gateway/smtp-smuggling.zeek` against SMTP sessions captured
during M0 test cases.

## Why containerized instead of installed

Kali rolling ships `libc6 2.42-13`; Kali's `zeek 5.1.1-0kali3` package
pins `libc6 < 2.38` and is therefore uninstallable. The openSUSE
Debian 12 build has the same libc mismatch. Running
`docker.io/zeek/zeek:lts` as a rootless container sidesteps the libc
problem entirely and is more faithful to how Zeek is actually
deployed in production.

## Running Zeek on a pcap in this project

```bash
# Stage files in /tmp because /run/host/mnt/... isn't visible to
# rootless Podman on Kali-in-NixOS.
mkdir -p /tmp/zeek-run/{pcaps,scripts,work}
cp results/pcaps/case-a1.pcap /tmp/zeek-run/pcaps/
cp detect/gateway/smtp-smuggling.zeek /tmp/zeek-run/scripts/

podman run --rm \
    --security-opt seccomp=unconfined \
    -v /tmp/zeek-run/pcaps:/pcaps:ro \
    -v /tmp/zeek-run/scripts:/scripts:ro \
    -v /tmp/zeek-run/work:/work:rw \
    -w /work \
    docker.io/zeek/zeek:lts \
    zeek -C -r /pcaps/case-a1.pcap /scripts/smtp-smuggling.zeek

cat /tmp/zeek-run/work/notice.log
```

**Flags that matter:**

- `-C` — ignore TCP checksums. Pcaps captured via `tcpdump` on a NIC
  with checksum offloading (most modern Linux hosts) have invalid
  checksums because the NIC computes them after tcpdump sees them.
  Without `-C`, Zeek drops every packet and logs "trace file likely
  has invalid TCP checksums." Always pass `-C` in this project.
- `-r FILE` — read pcap instead of live sniffing.
- `--security-opt seccomp=unconfined` — required on this host because
  the Podman seccomp profile is broken.

## Zeek output files

After a successful run, `/tmp/zeek-run/work/` contains:

- `conn.log` — one row per TCP connection, with 5-tuple, bytes, state.
- `smtp.log` — one row per SMTP transaction (MAIL FROM → RCPT TO →
  DATA → body → `.`). Zeek's SMTP analyzer synthesizes this from the
  reconstructed stream.
- `files.log` — one row per file extracted from an SMTP DATA body.
- `notice.log` — this is the important one for this project. Every
  rule-raised notice lands here. Filter with `grep -v '^#'` to get
  data rows.
- `reporter.log` — Zeek's own warnings/errors about the script or the
  pcap. Check this if the script produced no output.

## The project's Zeek script

`detect/gateway/smtp-smuggling.zeek` runs two detectors:

### Byte-pattern detector

Hooks the `smtp_data` event (from Zeek's SMTP analyzer), accumulates
client→server bytes per connection, and scans the buffer for
parser-ambiguous dot sequences: `\n.\n`, `\r.\r`, `\r\n.\n`, and
variants. Fires on raw harness→MTA traffic *before* any relay MTA
normalizes the bytes. Generic by construction: detects the
vulnerability class, not just the literal paper payloads.

### Transaction-rate detector

Hooks the `smtp_request` event, tracks DATA commands per originator
IP over a 2-second window, and fires the second time the same IP
issues DATA within the window. Catches the *post-relay* case where a
vulnerable sender has already laundered the smuggled bytes into two
clean SMTP connections to the receiver — which is what M0's tcpdump
sidecar (on the receiver's network namespace) actually captures.

Both detectors raise notices with the same type
(`SMTPSmuggling::Parser_Differential_Pattern`) so the M0 runner
treats them uniformly.

## Debugging a silent Zeek script

If your script runs without errors but produces no notice.log:

1. **Check `reporter.log`** first. Zeek puts script compile errors
   and runtime warnings there, not on stdout.
2. **Check `conn.log`**: `cat conn.log | grep -v '^#' | awk '{print
   $NF}'` should show `smtp` in the services column. If it shows `-`,
   Zeek's analyzer didn't engage — usually because the pcap is
   missing the TCP handshake or has bad checksums (see `-C` above).
3. **Add `print` statements** inside your event handlers. They print
   to stdout when you run `zeek -r ...`. Remember to remove them
   before committing.
4. **Verify the event is firing at all**: `zeek --help-events | grep
   smtp` shows all SMTP events the analyzer exposes. Common ones:
   `smtp_request`, `smtp_reply`, `smtp_data`, `file_new` for
   extracted attachments.

## Zeek event signature gotcha

Signatures changed between Zeek 5.x and 6.x for several SMTP events.
This project targets Zeek 8.x (the current `lts` tag). If you upgrade
the image and something breaks, check `/usr/local/zeek/share/zeek/base/protocols/smtp/`
inside the container for the canonical event declarations.

## When Zeek fights you

The plan originally included a fallback pure-Python detector at
`detect/gateway/python_proxy_detector.py` that produces the same
JSON notice format. It wasn't needed in M0 because the containerized
Zeek path worked on the first real pcap. If you hit a wall on Zeek
during M1 or M2, writing the Python fallback is a cheap ~30-line
escape hatch.
