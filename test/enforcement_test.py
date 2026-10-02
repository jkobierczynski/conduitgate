#!/usr/bin/env python3
"""Integration test: does conduitgate actually stop things reaching the device?

Deliberately built on raw sockets rather than a Modbus client library. A library
will not send a pipelined PDU, will not split a function code across TCP
segments, and will not emit UMAS — and those are exactly the cases worth
testing. The wire format is seven bytes of header; writing it by hand costs
nothing and removes a dependency whose API churns.

    go build -o conduitgate ./cmd/conduitgate
    python3 test/plcsim.py 5020 &
    ./conduitgate -listen 127.0.0.1:5502 -target 127.0.0.1:5020 &
    python3 test/enforcement_test.py

Override the ports with CG_PROXY_PORT and CG_DEVICE_PORT when those defaults
collide with something already running:

    CG_DEVICE_PORT=5021 CG_PROXY_PORT=5503 python3 test/enforcement_test.py

Exits non-zero on any unexpected outcome, so it is usable in CI.
"""
import os
import socket
import struct
import sys
import time

import identity

PROXY = ("127.0.0.1", int(os.environ.get("CG_PROXY_PORT", "5502")))
DIRECT = ("127.0.0.1", int(os.environ.get("CG_DEVICE_PORT", "5020")))

# Check the boundary before asserting anything past it. Pointing a suite at the
# wrong listener produces a failure several layers from its cause.
identity.expect(identity.PLCSIM, DIRECT, "device")
identity.expect(identity.CONDUITGATE, PROXY, "proxy")

EX_ILLEGAL_FUNCTION = 0x01
REG = 10  # holding register used for the enforcement assertions

failures: list[str] = []


def mbap(txid: int, uid: int, pdu: bytes) -> bytes:
    return struct.pack(">HHHB", txid, 0, len(pdu) + 1, uid) + pdu


def read_frame(sock: socket.socket) -> tuple[int, int, bytes]:
    head = recv_exactly(sock, 7)
    txid, proto, length, uid = struct.unpack(">HHHB", head)
    assert proto == 0, f"protocol id {proto}"
    return txid, uid, recv_exactly(sock, length - 1)


def recv_exactly(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed mid-frame")
        buf += chunk
    return buf


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{'  — ' + detail if detail else ''}")
    if not ok:
        failures.append(name)


def read_register(sock: socket.socket, addr: int, txid: int = 1) -> int:
    sock.sendall(mbap(txid, 1, struct.pack(">BHH", 0x03, addr, 1)))
    _, _, pdu = read_frame(sock)
    if pdu[0] & 0x80:
        raise AssertionError(f"read denied, exception 0x{pdu[1]:02X}")
    return struct.unpack(">H", pdu[2:4])[0]


def expect_exception(sock: socket.socket, pdu: bytes, txid: int = 1):
    sock.sendall(mbap(txid, 1, pdu))
    _, _, resp = read_frame(sock)
    return resp


def connect(addr) -> socket.socket:
    s = socket.create_connection(addr, timeout=5)
    s.settimeout(5)
    return s


# --------------------------------------------------------------------------
# Control experiment. If the write does not succeed against the bare device,
# nothing that follows proves anything.
# --------------------------------------------------------------------------
print("\nControl: write directly to the device, bypassing the proxy")
with connect(DIRECT) as s:
    before = read_register(s, REG)
    s.sendall(mbap(2, 1, struct.pack(">BHH", 0x06, REG, 0xDEAD)))
    _, _, resp = read_frame(s)
    after = read_register(s, REG, txid=3)
    check("device accepts a direct write", resp[0] == 0x06 and after == 0xDEAD,
          f"register {REG}: {before} -> {after}")
    # Restore, so the enforcement run starts from the original value.
    s.sendall(mbap(4, 1, struct.pack(">BHH", 0x06, REG, before)))
    read_frame(s)
    ORIGINAL = before

# --------------------------------------------------------------------------
# Enforcement. Same write, now through conduitgate.
# --------------------------------------------------------------------------
print("\nEnforcement: the same operations through conduitgate")
with connect(PROXY) as s:
    baseline = read_register(s, REG)
    check("permitted read succeeds through the proxy", baseline == ORIGINAL,
          f"register {REG} = {baseline}")

    resp = expect_exception(s, struct.pack(">BHH", 0x06, REG, 0xDEAD), txid=10)
    check("FC 6 write is refused with exception 0x01",
          resp == bytes([0x86, EX_ILLEGAL_FUNCTION]),
          f"response {resp.hex(' ')}")

    # The decisive assertion: the denial was enforcement, not logging.
    after = read_register(s, REG, txid=11)
    check("denied write never reached the device", after == baseline,
          f"register {REG} still {after}")

    # The connection survives a denial. An HMI polling through this proxy keeps
    # working; only the offending operation is refused.
    check("session survives the denial", read_register(s, REG, txid=12) == baseline)

    # FC 23 performs its write before its read and returns only read data.
    fc23 = struct.pack(">BHHHHB", 0x17, 0, 1, REG, 1, 2) + struct.pack(">H", 0xBEEF)
    resp = expect_exception(s, fc23, txid=13)
    check("FC 23 read/write is refused", resp == bytes([0x97, EX_ILLEGAL_FUNCTION]),
          f"response {resp.hex(' ')}")
    check("FC 23 write half never reached the device",
          read_register(s, REG, txid=14) == baseline)

    # UMAS, hiding inside a function code the spec lists as reserved.
    resp = expect_exception(s, bytes([0x5A, 0x00, 0x41, 0x00]), txid=15)
    check("UMAS ex_StopTask is refused", resp == bytes([0xDA, EX_ILLEGAL_FUNCTION]),
          f"response {resp.hex(' ')}")

    # FC 43 gated on the MEI byte: 14 permitted, 13 is a CANopen write tunnel.
    resp = expect_exception(s, bytes([0x2B, 0x0D, 0x00, 0x00]), txid=16)
    check("FC 43 MEI 13 CANopen tunnel is refused", resp[0] == 0xAB,
          f"response {resp.hex(' ')}")

    # Diagnostics subfunction 0x0004 isolates the device in one packet.
    resp = expect_exception(s, struct.pack(">BHH", 0x08, 0x0004, 0x0000), txid=17)
    check("FC 8 Force Listen Only Mode is refused", resp[0] == 0x88,
          f"response {resp.hex(' ')}")

# --------------------------------------------------------------------------
# Evasion. The cases a per-packet filter fails.
# --------------------------------------------------------------------------
print("\nEvasion: byte-stream framing")
with connect(PROXY) as s:
    baseline = read_register(s, REG)

    # Split so the function-code byte arrives in a TCP segment of its own,
    # after the MBAP header. Any filter matching at a fixed packet offset misses
    # this write entirely.
    wire = mbap(20, 1, struct.pack(">BHH", 0x06, REG, 0xDEAD))
    for piece in (wire[:7], wire[7:8], wire[8:]):
        s.sendall(piece)
        time.sleep(0.02)
    _, _, resp = read_frame(s)
    check("write split across three segments is still refused",
          resp == bytes([0x86, EX_ILLEGAL_FUNCTION]), f"response {resp.hex(' ')}")
    check("segmented write never reached the device",
          read_register(s, REG, txid=21) == baseline)

    # Three PDUs coalesced into one segment. conduitgate must frame all three
    # and decide each independently.
    #
    # Note on the oracle: pymodbus's server answers only the FIRST pipelined
    # request and silently drops the remainder — verified to behave identically
    # with the proxy removed from the path. So this asserts on the two responses
    # that are attributable to conduitgate itself (the allowed read it relayed,
    # and the exception it synthesized) and does not expect a reply to the
    # trailing read. A device that pipelines properly would answer all three.
    batch = (
        mbap(30, 1, struct.pack(">BHH", 0x03, REG, 1))
        + mbap(31, 1, struct.pack(">BHH", 0x06, REG, 0xDEAD))
        + mbap(32, 1, struct.pack(">BHH", 0x03, REG, 1))
    )
    s.sendall(batch)
    results = {}
    s.settimeout(1.5)
    try:
        while len(results) < 3:
            txid, _, pdu = read_frame(s)
            results[txid] = pdu
    except (TimeoutError, socket.timeout):
        pass
    s.settimeout(5)

    check("pipelined batch: middle write denied",
          results.get(31) == bytes([0x86, EX_ILLEGAL_FUNCTION]),
          f"responses seen: {sorted(results)}")
    # pymodbus also coalesces the two reads conduitgate forwards and answers
    # only one of them, so assert that a read got through without pinning which.
    # Per-PDU proof that all three were framed and decided independently is in
    # conduitgate's own audit log (ALLOW 30 / DENY 31 / ALLOW 32).
    reads = [t for t in (30, 32) if results.get(t, b"\x00")[0] == 0x03]
    check("pipelined batch: reads still allowed through", bool(reads),
          f"answered: {reads}; responses seen: {sorted(results)}")
    check("pipelined write never reached the device",
          read_register(s, REG, txid=33) == baseline)

print()
if failures:
    print(f"{len(failures)} failure(s): {', '.join(failures)}")
    sys.exit(1)
print("all enforcement assertions passed")
