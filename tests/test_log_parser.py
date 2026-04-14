"""Log parser tests with hand-crafted Postfix and Exim log fixtures."""
from detect.logs.parse_mail_log import (
    parse_postfix_log,
    parse_exim_log,
    detect_multi_queue_from_one_client,
    detect_for_pcap_case,
)


_POSTFIX_FIXTURE = """\
Apr 14 12:21:08 sender postfix/smtpd[383]: D1132842816: client=unknown[10.89.2.20]
Apr 14 12:21:08 sender postfix/cleanup[386]: D1132842816: message-id=<abc@labnet.test>
Apr 14 12:21:08 sender postfix/qmgr[380]: D1132842816: from=<alice@labnet.test>, size=557
Apr 14 12:21:08 sender postfix/smtpd[383]: D1F17842817: client=unknown[10.89.2.20]
Apr 14 12:21:08 sender postfix/cleanup[386]: D1F17842817: message-id=<def@sender.labnet.test>
"""

_EXIM_FIXTURE = """\
2026-04-14 12:21:08 1abcde-000001-XY <= alice@labnet.test H=sender [10.89.2.20] P=esmtp S=600
2026-04-14 12:21:08 1abcde-000002-XY <= attacker@evil.test H=sender [10.89.2.20] P=esmtp S=400
"""


def test_parse_postfix_extracts_queue_and_client(tmp_path):
    log = tmp_path / "mail.log"
    log.write_text(_POSTFIX_FIXTURE)
    rows = parse_postfix_log(log)
    assert len(rows) == 2
    assert rows[0]["queue_id"] == "D1132842816"
    assert rows[0]["client_ip"] == "10.89.2.20"
    assert rows[1]["queue_id"] == "D1F17842817"


def test_detect_multi_queue_fires_on_smuggling_shape(tmp_path):
    log = tmp_path / "mail.log"
    log.write_text(_POSTFIX_FIXTURE)
    rows = parse_postfix_log(log)
    notices = detect_multi_queue_from_one_client(rows)
    assert len(notices) == 1
    assert notices[0]["client_ip"] == "10.89.2.20"
    assert notices[0]["count"] == 2


def test_detect_multi_queue_quiet_on_single_email(tmp_path):
    log = tmp_path / "mail.log"
    log.write_text(
        "Apr 14 12:21:08 sender postfix/smtpd[383]: ABC123: client=unknown[10.89.2.20]\n"
    )
    rows = parse_postfix_log(log)
    notices = detect_multi_queue_from_one_client(rows)
    assert notices == []


def test_parse_exim_extracts_client_ip(tmp_path):
    log = tmp_path / "mainlog"
    log.write_text(_EXIM_FIXTURE)
    rows = parse_exim_log(log)
    assert len(rows) == 2
    assert rows[0]["sender"] == "alice@labnet.test"
    assert rows[1]["sender"] == "attacker@evil.test"
    assert all(r["client_ip"] == "10.89.2.20" for r in rows)


def test_detect_for_pcap_case_merges_sources(tmp_path):
    (tmp_path / "mail.log").write_text(_POSTFIX_FIXTURE)
    (tmp_path / "mainlog").write_text(_EXIM_FIXTURE)
    notices = detect_for_pcap_case(tmp_path)
    types = {n["type"] for n in notices}
    assert "multi-queue-per-client" in types
    assert "exim-multi-receive" in types
