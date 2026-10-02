#!/usr/bin/env python3
"""Integration test for the response path: does conduitgate protect the CLIENT?

The request-side test asks whether the device is safe from the client. This one
asks the other question, which a read-only proxy is just as responsible for: is
the engineering workstation safe from a faulty or compromised device?

    go build -o conduitgate ./cmd/conduitgate
    python3 test/rogue_device.py 5030 &
    ./conduitgate -listen 127.0.0.1:5502 -target 127.0.0.1:5030 &
    python3 test/response_test.py

Ports come from CG_PROXY_PORT (default 5502). The rogue device selects its
misbehaviour from the unit id, so every case runs against one listener.
"""
import os
import socket
import struct
import sys

import identity

PROXY = ("127.0.0.1", int(os.environ.get("CG_PROXY_PORT", "5502")))

identity.expect(identity.CONDUITGATE, PROXY, "proxy")

EX_SERVER_DEVICE_FAILURE = 0x04
REG = 10

failures: list[str] = []


def mbap(txid: int, uid: int, pdu: bytes) -> bytes:
    return struct.pack(">HHHB", txid, 0, len(pdu) + 1, uid) + pdu


def recv_exactly(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed mid-frame")
        buf += chunk
    return buf


def read_frame(sock: socket.socket):
    txid, proto, length, uid = struct.unpack(">HHHB", recv_exactly(sock, 7))
    assert proto == 0, f"protocol id {proto}"
    return txid, uid, recv_exactly(sock, length - 1)


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{'  — ' + detail if detail else ''}")
    if not ok:
        failures.append(name)


def ask(uid: int, txid: int = 1, quantity: int = 2):
    """One read through the proxy to the given rogue-device persona."""
    s = socket.create_connection(PROXY, timeout=5)
    s.settimeout(3)
    try:
        s.sendall(mbap(txid, uid, struct.pack(">BHH", 0x03, REG, quantity)))
        return s, read_frame(s)
    except Exception:
        s.close()
        raise


print("\nControl: an honest device is relayed unchanged")
s, (_, _, pdu) = ask(6)
check("correct response passes through", pdu[0] == 0x03 and pdu[1] == 4,
      f"pdu {pdu.hex(' ')}")
s.close()

print("\nMalformed responses are refused, and the client is told so")

s, (_, _, pdu) = ask(1)
check("byte count larger than requested is refused",
      pdu == bytes([0x83, EX_SERVER_DEVICE_FAILURE]), f"pdu {pdu.hex(' ')}")
s.close()

s, (_, _, pdu) = ask(2)
check("byte count disagreeing with PDU length is refused",
      pdu == bytes([0x83, EX_SERVER_DEVICE_FAILURE]), f"pdu {pdu.hex(' ')}")
s.close()

s, (_, _, pdu) = ask(3)
check("a response with the wrong function code is refused",
      pdu == bytes([0x83, EX_SERVER_DEVICE_FAILURE]), f"pdu {pdu.hex(' ')}")
s.close()

s, (_, _, pdu) = ask(4)
check("an undefined exception code is refused",
      pdu == bytes([0x83, EX_SERVER_DEVICE_FAILURE]), f"pdu {pdu.hex(' ')}")
s.close()

print("\nUnsolicited responses are dropped")
s, (txid, _, pdu) = ask(5, txid=42)
ok_first = pdu[0] == 0x03 and txid == 42
extra = None
try:
    s.settimeout(1.5)
    extra = read_frame(s)
except (TimeoutError, socket.timeout):
    pass
except ConnectionError:
    pass
s.close()
check("the solicited response is relayed", ok_first, f"txid {txid}, pdu {pdu.hex(' ')}")
check("the unsolicited second response never reaches the client", extra is None,
      f"leaked {extra}")

print()
if failures:
    print(f"{len(failures)} failure(s): {', '.join(failures)}")
    sys.exit(1)
print("all response-path assertions passed")
