#!/usr/bin/env python3
"""A deliberately misbehaving Modbus/TCP device.

pymodbus is a well-behaved server, which makes it useless for testing the
response path — you cannot check that a proxy refuses a malformed reply if
nothing malformed is ever sent. This stands in for a faulty or compromised PLC.

The misbehaviour is selected by the UNIT ID in the request, so one server on one
port covers every case:

    unit 1  byte count larger than the quantity requested
    unit 2  byte count disagreeing with the actual PDU length
    unit 3  a response carrying a different function code
    unit 4  an exception code the specification does not define
    unit 5  a correct response, followed by an unsolicited second one
    unit 6  correct behaviour (the control)

    python3 test/rogue_device.py 5030
"""
import socket
import struct
import sys
import threading


def mbap(txid: int, uid: int, pdu: bytes) -> bytes:
    return struct.pack(">HHHB", txid, 0, len(pdu) + 1, uid) + pdu


def recv_exactly(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError
        buf += chunk
    return buf


def handle(conn: socket.socket) -> None:
    with conn:
        while True:
            try:
                head = recv_exactly(conn, 7)
            except (ConnectionError, OSError):
                return
            txid, _, length, uid = struct.unpack(">HHHB", head)
            try:
                pdu = recv_exactly(conn, length - 1)
            except (ConnectionError, OSError):
                return

            fc = pdu[0]
            quantity = struct.unpack(">H", pdu[3:5])[0] if len(pdu) >= 5 else 1
            honest = bytes([fc, quantity * 2]) + bytes(quantity * 2)

            if uid == 1:
                # Two extra registers nobody asked for, self-consistently framed
                # so that only a request-aware check catches it.
                n = quantity * 2 + 4
                conn.sendall(mbap(txid, uid, bytes([fc, n]) + bytes(n)))
            elif uid == 2:
                # Declares one length, carries another.
                conn.sendall(mbap(txid, uid, bytes([fc, quantity * 2 + 2]) + bytes(quantity * 2)))
            elif uid == 3:
                conn.sendall(mbap(txid, uid, bytes([0x06, 0x00, 0x0A, 0xDE, 0xAD])))
            elif uid == 4:
                conn.sendall(mbap(txid, uid, bytes([fc | 0x80, 0x07])))
            elif uid == 5:
                conn.sendall(mbap(txid, uid, honest))
                # Nothing asked for this one.
                conn.sendall(mbap((txid + 1000) & 0xFFFF, uid, honest))
            else:
                conn.sendall(mbap(txid, uid, honest))


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5030
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(8)
    print(f"rogue_device listening on 127.0.0.1:{port}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
