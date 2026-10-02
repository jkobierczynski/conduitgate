#!/usr/bin/env python3
"""Integration test for policy scoping across multiple targets.

Two listeners front the SAME physical device with deliberately disjoint scopes:

    narrow  127.0.0.1:5520 -> plcsim  unit 1, holding registers 0-19
    wide    127.0.0.1:5521 -> plcsim  unit 2, holding registers 40-59 + input 0-7

Everything the device would happily answer is available through one listener and
refused through the other, which is the property worth proving: the listen
address selects the scope, and the two do not leak into each other.

    go build -o conduitgate ./cmd/conduitgate
    python3 test/plcsim.py 5020 &
    ./conduitgate -policy test/policy-test.json &
    python3 test/policy_test.py

Ports come from CG_NARROW_PORT and CG_WIDE_PORT.
"""
import os
import socket
import struct
import sys

import identity

NARROW = ("127.0.0.1", int(os.environ.get("CG_NARROW_PORT", "5520")))
WIDE = ("127.0.0.1", int(os.environ.get("CG_WIDE_PORT", "5521")))

identity.expect(identity.CONDUITGATE, NARROW, "narrow target")
identity.expect(identity.CONDUITGATE, WIDE, "wide target")

EX_ILLEGAL_FUNCTION = 0x01
EX_ILLEGAL_DATA_ADDRESS = 0x02

failures: list[str] = []
txid = [0]


def mbap(tx: int, uid: int, pdu: bytes) -> bytes:
    return struct.pack(">HHHB", tx, 0, len(pdu) + 1, uid) + pdu


def recv_exactly(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed mid-frame")
        buf += chunk
    return buf


def read_frame(sock: socket.socket):
    tx, proto, length, uid = struct.unpack(">HHHB", recv_exactly(sock, 7))
    assert proto == 0
    return tx, uid, recv_exactly(sock, length - 1)


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{'  — ' + detail if detail else ''}")
    if not ok:
        failures.append(name)


def exchange(sock: socket.socket, uid: int, pdu: bytes) -> bytes:
    txid[0] += 1
    sock.sendall(mbap(txid[0], uid, pdu))
    _, _, resp = read_frame(sock)
    return resp


def read_regs(sock: socket.socket, uid: int, start: int, count: int, fc: int = 0x03) -> bytes:
    return exchange(sock, uid, struct.pack(">BHH", fc, start, count))


def connect(addr) -> socket.socket:
    s = socket.create_connection(addr, timeout=5)
    s.settimeout(5)
    return s


narrow = connect(NARROW)
wide = connect(WIDE)

print("\nEach target serves its own window")
r = read_regs(narrow, 1, 0, 1)
check("narrow: first register of its window", r[0] == 0x03, f"pdu {r.hex(' ')}")
r = read_regs(narrow, 1, 19, 1)
check("narrow: last register of its window", r[0] == 0x03, f"pdu {r.hex(' ')}")
r = read_regs(wide, 2, 40, 1)
check("wide: first register of its window", r[0] == 0x03, f"pdu {r.hex(' ')}")
r = read_regs(wide, 2, 59, 1)
check("wide: last register of its window", r[0] == 0x03, f"pdu {r.hex(' ')}")
r = read_regs(wide, 2, 0, 1, fc=0x04)
check("wide: input registers, which narrow does not permit at all",
      r[0] == 0x04, f"pdu {r.hex(' ')}")

print("\nThe windows do not leak between targets")
r = read_regs(narrow, 1, 40, 1)
check("narrow refuses the wide target's window",
      r == bytes([0x83, EX_ILLEGAL_DATA_ADDRESS]), f"pdu {r.hex(' ')}")
r = read_regs(wide, 2, 0, 1)
check("wide refuses the narrow target's window",
      r == bytes([0x83, EX_ILLEGAL_DATA_ADDRESS]), f"pdu {r.hex(' ')}")
r = read_regs(narrow, 1, 0, 1, fc=0x04)
check("narrow refuses input registers as an unnamed function",
      r == bytes([0x84, EX_ILLEGAL_FUNCTION]), f"pdu {r.hex(' ')}")

print("\nUnit ids do not leak between targets")
r = read_regs(narrow, 2, 40, 1)
check("narrow does not front the wide target's unit 2",
      r == bytes([0x83, EX_ILLEGAL_FUNCTION]), f"pdu {r.hex(' ')}")
r = read_regs(wide, 1, 0, 1)
check("wide does not front the narrow target's unit 1",
      r == bytes([0x83, EX_ILLEGAL_FUNCTION]), f"pdu {r.hex(' ')}")
for uid in (0, 7, 255):
    r = read_regs(narrow, uid, 0, 1)
    check(f"narrow: unit {uid} is unreachable",
          r == bytes([0x83, EX_ILLEGAL_FUNCTION]), f"pdu {r.hex(' ')}")

print("\nWindow edges hold on both targets")
r = read_regs(narrow, 1, 20, 1)
check("narrow: one register past its window",
      r == bytes([0x83, EX_ILLEGAL_DATA_ADDRESS]), f"pdu {r.hex(' ')}")
r = read_regs(narrow, 1, 19, 2)
check("narrow: a read straddling its far edge",
      r == bytes([0x83, EX_ILLEGAL_DATA_ADDRESS]), f"pdu {r.hex(' ')}")
r = read_regs(wide, 2, 59, 2)
check("wide: a read straddling its far edge",
      r == bytes([0x83, EX_ILLEGAL_DATA_ADDRESS]), f"pdu {r.hex(' ')}")

print("\nPer-unit flags apply per target")
r = exchange(narrow, 1, bytes([0x0B]))
check("narrow: the event counter is denied for its unit",
      r == bytes([0x8B, EX_ILLEGAL_FUNCTION]), f"pdu {r.hex(' ')}")
r = exchange(wide, 2, bytes([0x0B]))
check("wide: the event counter is permitted for its unit",
      r[0] == 0x0B, f"pdu {r.hex(' ')}")

print("\nClassification still applies underneath every policy")
for sock, uid, label in ((narrow, 1, "narrow"), (wide, 2, "wide")):
    r = exchange(sock, uid, struct.pack(">BHH", 0x06, 0, 0xDEAD))
    check(f"{label}: a write is still refused",
          r == bytes([0x86, EX_ILLEGAL_FUNCTION]), f"pdu {r.hex(' ')}")
    r = exchange(sock, uid, bytes([0x5A, 0x00, 0x41, 0x00]))
    check(f"{label}: UMAS is still refused",
          r == bytes([0xDA, EX_ILLEGAL_FUNCTION]), f"pdu {r.hex(' ')}")

check("both sessions survived every denial",
      read_regs(narrow, 1, 0, 1)[0] == 0x03 and read_regs(wide, 2, 40, 1)[0] == 0x03)

narrow.close()
wide.close()

print()
if failures:
    print(f"{len(failures)} failure(s): {', '.join(failures)}")
    sys.exit(1)
print("all policy assertions passed")
