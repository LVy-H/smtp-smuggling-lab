##! SMTP smuggling detection.
##!
##! This script runs two detectors against SMTP traffic seen by Zeek:
##!
##!   (1) Byte-pattern detector. Scans the client->server raw bytes
##!       for parser-ambiguous dot sequences that indicate a smuggling
##!       attempt was placed on the wire. This fires against the
##!       original harness->MTA traffic (attack ingress), before any
##!       relay MTA normalizes the bytes.
##!
##!   (2) Transaction-rate detector. Counts completed SMTP transactions
##!       per originator IP over a short window and raises a notice
##!       when the same client delivers multiple distinct emails in
##!       rapid succession. This fires against the post-relay traffic
##!       (MTA->MTA) after a vulnerable sender has "laundered" the
##!       smuggled bytes into two well-formed SMTP connections.
##!
##! Both detectors write to notice.log with the same Notice::Type so
##! the M0 runner can treat them uniformly.

@load base/frameworks/notice
@load base/protocols/smtp
@load base/protocols/conn

module SMTPSmuggling;

export {
    redef enum Notice::Type += {
        Parser_Differential_Pattern,
    };
}

# ---------- Byte-pattern detector (detector 1) ----------

# Per-connection client->server byte buffer, keyed by connection UID.
global stream_buf: table[string] of string &default="";

event connection_established(c: connection)
    {
    if ( c$id$resp_p == 25/tcp )
        stream_buf[c$uid] = "";
    }

event smtp_data(c: connection, is_orig: bool, data: string)
    {
    if ( ! is_orig )
        return;
    stream_buf[c$uid] += data;
    }

event connection_state_remove(c: connection) &priority=-5
    {
    if ( c$uid !in stream_buf )
        return;
    local body = stream_buf[c$uid];
    delete stream_buf[c$uid];

    # Parser-ambiguous dot-sequence patterns without embedded NULs
    # (Zeek string literals don't accept \x00; NUL variants would
    # need dynamic construction — out of scope for M0).
    local patterns: vector of string = vector(
        "\x0a.\x0a",
        "\x0d.\x0d",
        "\x0d\x0a.\x0a",
        "\x0a.\x0d\x0a",
        "\x0d.\x0d\x0a",
        "\x0d\x0a.\x0d"
    );

    local i: count = 0;
    while ( i < |patterns| )
        {
        if ( patterns[i] in body )
            {
            NOTICE([
                $note=Parser_Differential_Pattern,
                $msg=fmt("pattern match: index=%d (byte-level)", i),
                $conn=c,
                $identifier=cat("bytepat", c$uid, i),
                $suppress_for=1hr
            ]);
            return;
            }
        ++i;
        }
    }

# ---------- Transaction-rate detector (detector 2) ----------

# Track SMTP transaction count per originator IP within a short window.
global tx_count: table[addr] of count &default=0 &create_expire=5sec;
global tx_last: table[addr] of time &default=double_to_time(0) &create_expire=5sec;

event smtp_request(c: connection, is_orig: bool, command: string, arg: string)
    {
    if ( ! is_orig )
        return;
    if ( to_lower(command) != "data" )
        return;
    local src = c$id$orig_h;
    local now = network_time();
    local prev = tx_last[src];
    if ( prev != double_to_time(0) && now - prev < 2sec )
        {
        tx_count[src] += 1;
        NOTICE([
            $note=Parser_Differential_Pattern,
            $msg=fmt("tx-rate: %s emitted multiple DATA transactions within 2s (count=%d)", src, tx_count[src] + 1),
            $conn=c,
            $identifier=cat("txrate", src),
            $suppress_for=1hr
        ]);
        }
    else
        {
        tx_count[src] = 0;
        }
    tx_last[src] = now;
    }
