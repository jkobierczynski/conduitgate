#!/usr/bin/env python3
"""Identify what is actually listening on a port, before a suite asserts anything.

Every confusing failure in this harness so far has had the same shape: the test
was pointed at the wrong thing, and the symptom appeared three layers away from
the cause. A read refused with exception 0x04 is a long way from "the rogue
device is on plcsim's port".

So each suite checks the boundary first. The probes are cheap, read-only and
have no side effects — no register is written to work out what something is.

The fingerprints, all from one well-formed read plus one read carrying a single
trailing byte:

    conduitgate  refuses the trailing byte with 0x83 0x03. Nothing else does:
                 a device tolerates the extra byte, because tolerating it is
                 exactly the leniency this proxy exists to stop.
    plcsim       answers both identically, byte count 2, value in 1000..1099.
    rogue        answers with a byte count that does not match the quantity
                 requested, which is its whole purpose.

Run directly to inspect a port:  python3 test/identity.py 5020
"""
import socket
import struct
import sys

# What a suite can require.
CONDUITGATE = "conduitgate"
PLCSIM = "plcsim"
ROGUE = "rogue"

DESCRIPTIONS = {
    CONDUITGATE: "a conduitgate proxy",
    PLCSIM: "the plcsim simulated device",
    ROGUE: "the rogue (deliberately misbehaving) device",
}


def _ask(addr, pdu, uid=1, timeout=3):
    """One request/response. Returns the response PDU, or None."""
    try:
        s = socket.create_connection(addr, timeout=timeout)
        s.settimeout(timeout)
        try:
            s.sendall(struct.pack(">HHHB", 1, 0, len(pdu) + 1, uid) + pdu)
            head = b""
            while len(head) < 7:
                chunk = s.recv(7 - len(head))
                if not chunk:
                    return None
                head += chunk
            _, proto, length, _ = struct.unpack(">HHHB", head)
            if proto != 0 or length < 2:
                return None
            body = b""
            while len(body) < length - 1:
                chunk = s.recv(length - 1 - len(body))
                if not chunk:
                    return None
                body += chunk
            return body
        finally:
            s.close()
    except OSError:
        return None


def classify(addr, uid=1):
    """Return (kind, detail). kind is one of the constants above, or None."""
    well_formed = struct.pack(">BHH", 0x03, 10, 1)

    # The trailing byte is the discriminator: only an enforcing proxy answers a
    # PDU one byte longer than its function code allows with 0x83 0x03.
    #
    # A device may do one of two things instead — tolerate the extra byte and
    # answer normally, or close the connection. Both are reasonable and both
    # vary by implementation, so neither is treated as a failure here: the probe
    # falls through to a well-formed read on a fresh connection. Treating a
    # closed connection as fatal is exactly the bug this comment replaces.
    trailing = _ask(addr, well_formed + b"\xff", uid=uid)
    if trailing == bytes([0x83, 0x03]):
        return CONDUITGATE, "refused a PDU with a trailing byte, as an enforcing proxy should"

    strict = trailing is None  # closed the connection rather than answering
    aside = "; it closed the connection on a malformed PDU, as a device may" if strict else ""

    good = _ask(addr, well_formed, uid=uid)
    if good is None:
        if strict:
            return None, "nothing answered on this port"
        return None, f"answered a malformed probe with {trailing.hex(' ')} but not a well-formed read"

    if good[0] & 0x80:
        if strict:
            # It closed on the malformed probe, so it is a device, not a proxy.
            return None, (f"a Modbus device that refused a plain read with exception "
                          f"0x{good[1]:02X}, so it is not plcsim{aside}")
        # An exception to a plain read from something that tolerated the
        # malformed one: most likely a policy-scoped proxy whose rules do not
        # cover the probe.
        return CONDUITGATE, (f"refused a plain read with exception 0x{good[1]:02X}, "
                             "which a policy-scoped proxy does for an out-of-scope probe")

    if good[0] == 0x03 and len(good) >= 2:
        declared = good[1]
        if declared != 2:
            return ROGUE, (f"returned byte count {declared} for a one-register read, "
                           f"which is the rogue device's signature{aside}")
        if len(good) == 4:
            value = struct.unpack(">H", good[2:4])[0]
            if 1000 <= value < 1100:
                return PLCSIM, (f"returned register 10 = {value}, "
                                f"plcsim's holding-register block{aside}")
            return None, f"a Modbus device, but register 10 = {value}, not plcsim's range{aside}"

    return None, f"answered a read with {good.hex(' ')}, which matches nothing known"


def expect(kind, addr, label=""):
    """Exit with a clear message unless `addr` is what the suite needs."""
    where = f"{addr[0]}:{addr[1]}"
    if label:
        where = f"{label} ({where})"

    found, detail = classify(addr)
    if found == kind:
        return

    print(f"\nWRONG THING ON {where}")
    print(f"  expected: {DESCRIPTIONS[kind]}")
    if found is None:
        print(f"  found:    unrecognised — {detail}")
    else:
        print(f"  found:    {DESCRIPTIONS[found]} — {detail}")
    print()
    print("  Nothing below this point would mean anything, so the suite stops here.")
    print("  test/run_all.sh brings the whole harness up on the right ports.")
    sys.exit(2)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5020
    host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    kind, detail = classify((host, port))
    name = DESCRIPTIONS.get(kind, "nothing recognised")
    print(f"{host}:{port} — {name}\n  {detail}")
