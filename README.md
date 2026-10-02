# conduitgate

A read-only enforcement proxy for Modbus/TCP.

It sits between a client and an industrial device, parses every request, and
forwards only the reads an operator has explicitly permitted — scoped by source
address, unit id, function code and register range. Everything else is refused
with a well-formed Modbus exception, and recorded with a reason you can look up.

Responses are validated too. A read-only proxy that checks only requests
protects the device from the client and leaves the client undefended against the
device, which is the wrong half of the problem to solve in a vendor-access
deployment.

```
client ──▶ conduitgate ──▶ PLC
       ◀──             ◀──
           ▲
           └─ parse, validate against policy, re-serialize from parsed fields
```

> **Status: working, not production-proven.** Validated against simulators,
> captured traffic and fuzzing. Never run against production hardware, never
> certified, no support. See [Limitations](#limitations) before putting it
> anywhere that matters.

## Why this exists

Per-function-code filtering is not new — Tofino did it in 2010, and Palo Alto,
Moxa and TXOne all ship it today. Two things are missing from the open-source
landscape, and both are the reason this exists.

**Nothing open-source terminates the connection and speaks the protocol.**
Snort, Suricata and nftables-based filters drop *packets*. A dropped packet
makes the client hang and retransmit, which an engineer debugs as a network
fault and an operator experiences as an outage of unknown cause. conduitgate
answers with a proper exception, and the session stays up — only the offending
operation is refused, so a polling HMI keeps working.

**Rule engines are default-allow.** You write signatures for what to deny, and
anything you did not enumerate passes. That is the wrong posture here, for a
reason worth stating concretely: see [UMAS](#the-case-for-default-deny).

## Quick start

Go 1.22 or later. No dependencies.

```sh
go build -o conduitgate ./cmd/conduitgate

# Bench mode: one global read-only rule, every unit id and address reachable.
./conduitgate -listen 127.0.0.1:5502 -target 127.0.0.1:502

# Deployment mode: an operator-authored rule set.
./conduitgate -policy policy/example.json
```

Why a denial happened:

```sh
./conduitgate -explain list
./conduitgate -explain fc.umas
```

## Policy

```jsonc
{
  "version": 1,
  "fail_mode": "closed",
  "sources": ["10.40.0.0/24"],

  "session": {
    "max_outstanding": 16,
    "pending_ttl_seconds": 30,
    "idle_timeout_seconds": 120,
    "max_conns_per_source": 4,
    "half_open_timeout_seconds": 5
  },

  "targets": [
    {
      "name": "line3-plc",
      "listen": "0.0.0.0:5021",
      "address": "10.20.30.11:502",
      "sources": ["10.40.0.55/32"],

      "units": [
        {
          "id": 1,
          "description": "Line 3 main PLC. Process values only.",
          "rules": [
            {
              "fc": [3],
              "start": 0,
              "count": 20,
              "note": "Process values 40001-40020 in HMI numbering."
            }
          ]
        }
      ]
    }
  ]
}
```

A few things about this format are deliberate.

**A policy narrows; it never widens.** Classification runs first and cannot be
overridden from a file. Name a write function code in a rule and the policy is
*rejected at load*, with an error saying so. An operator can make this stricter
than read-only and cannot make it looser.

**Flags are named for denial.** `deny_device_id`, `deny_event_counter` — so an
omitted field is never more permissive than the built-in posture.

**Addresses are protocol addresses, 0-based.** Holding register 40001 in HMI
numbering is `"start": 0` here. The policy is written in the same numbers the
filter compares against, because a translation layer between policy and
enforcement is somewhere the two can disagree.

**Unknown keys are an error.** A mistyped key is a missing rule, and a missing
rule in a security policy should be loud.

**The listen address selects the target.** One client connection maps to exactly
one device connection, which is what keeps response correlation tractable. Two
targets may front the same device with different scopes.

**Adjacent rules do not merge.** A read straddling `0..9` and `10..19` is
refused even though both windows are permitted — allowing it would mean the
windows do not mean what they say. Write the union as one rule if that is what
you meant.

## What is permitted

| FC | | Notes |
|---|---|---|
| 1, 2 | Read Coils / Discrete Inputs | address-scoped |
| 3, 4 | Read Holding / Input Registers | address-scoped |
| 11 | Get Comm Event Counter | on by default, per-unit opt-out |
| 43 / MEI 14 | Read Device Identification | object id bounded to 0x06 |
| 8 | Diagnostics | **off by default**, opt-in with a subfunction allowlist |

Everything else is refused. Some of the refusals are not obvious.

**FC 23 (Read/Write Multiple Registers)** carries both operations in one PDU and
the specification performs *the write before the read*. The response contains
only the read data, so a permitted FC 23 returns an ordinary-looking read
response while the write happens silently. The write quantity field is
constrained to 1–121, so no legal FC 23 omits its write half — there is no
read-only subset to permit, and no address range that makes it safe. A filter
written as "does this PDU read registers?" passes it. That is the most common
way a read-only Modbus filter turns out not to be one.

**FC 43** is decided by its MEI type byte, never the function code. MEI 14 is
genuinely read-only; **MEI 13 is a read *and write* path into the CANopen object
dictionary** — a tunnel straight through a filter that gates on FC 43 alone.

**FC 8** needs a subfunction allowlist, not a yes/no. Subfunction 0x0004 (Force
Listen Only Mode) isolates the device and returns no response: a single-packet
denial of service. 0x0000 echoes arbitrary bytes, giving a covert channel and an
amplifier through your own proxy.

**FC 20 (Read File Record)** is nominally a read, but on Modicon-family devices
file records back configuration and program storage. It is a program upload.

### The case for default-deny

Function code **0x5A (90) is Schneider Electric's UMAS engineering protocol**,
and the specification files it under *reserved* rather than in the user-defined
ranges (65–72, 100–110). A filter that default-denies the user-defined ranges
while treating "reserved" as unused passes the entire Modicon engineering
protocol. Inside it:

```
UMAS 0x21  pu_WriteMemoryBlock   arbitrary memory write, no reservation needed
UMAS 0x40  ex_StartTask          start the PLC, absent an application password
UMAS 0x41  ex_StopTask           STOP the PLC, absent an application password
UMAS 0x30/31/32                  program download
```

Nobody writes a signature for a function code they have not enumerated. The
vendor sub-protocol problem is unbounded — Schneider today, someone else next
year — and default-deny bounds the work on all of it to zero. conduitgate
refuses 0x5A at classification and never parses the layer beneath it: a UMAS
parser this tool does not contain is one that cannot contain a bug.

## Design notes

**Classify before you decode, and never decode what you will not allow.** Only
six function codes' worth of parsing ever runs on hostile input.

**Re-originate; do not forward.** Every PDU is parsed into a typed structure,
validated, and then *serialized afresh* from those fields. The bytes that
arrived are never passed on. This makes an entire class of attack unreachable:
the MBAP length desync, where your filter frames a message as `[read][padding]`
and the device frames it as `[read][write]`, because the two resolve a
self-contradictory length field differently. Nothing you did not fully
understand ever reaches the device, so you are not relying on the device
agreeing with you.

**Frame the byte stream, never packets.** A PDU may span any number of TCP
segments and several may coalesce into one. Every per-packet Modbus filter is
evaded by putting the function-code byte in a segment of its own.

**Bound the half-open frame separately from the idle session.** A client that
sends a seven-byte header declaring 253 bytes and then stops is not idle — bytes
arrived, just never enough to decide anything about — so the idle timeout does
not cover it. It is the Modbus shape of a slowloris, and the answer is a short
timeout on an incomplete frame, deliberately not a tarpit: an inline element in
a control path should release resources rather than hold connections open on
purpose.

**Never resynchronize.** MBAP has no sync pattern or frame delimiter, so after a
framing error there is no sound way to find the next boundary — the attacker
chooses where you land. Framing errors are sticky and the connection is torn
down.

**Correlate on (transaction id, unit id), with duplicates queued.** The
specification does not require transaction identifiers to be unique, non-zero or
monotonic, and real clients reuse them; behind a gateway the unit id selects
different physical hardware. Keying on a uniqueness assumption the wire does not
guarantee is a state-corruption bug waiting for a badly behaved client.

**One client connection, one device connection.** Multiplexing several clients
onto one device connection is what real deployments eventually want, since many
PLCs accept only two or three — but it requires rewriting transaction
identifiers and is deliberately not in this version.

## Protocol scope

Modbus/TCP only, and the other obvious candidates are out for reasons worth
recording rather than rediscovering.

**DNP3** — Secure Authentication v5 makes a re-originating proxy an outage
generator. Link-layer CRCs must be recomputed and transport fragments rewritten,
so every critical ASDU fails HMAC verification; the outstation counts
authentication failures and resets the association. Separately, FC 2 WRITE
cannot simply be blocked — the master needs it to clear the outstation's
`DEVICE_RESTART` IIN bit, or masters loop re-initializing forever. "Read-only
DNP3" means full object group/variation/index parsing, not function-code
filtering.

**S7comm-plus (S7-1200 v4+, S7-1500)** — not a function-code protocol at all,
but a runtime-discovered object/attribute model with a per-message integrity
value. Siemens moved V2.x/V3.x firmware to certificate-based PG/HMI
communication over TLS on port 102, so a parsing proxy is a MITM by
construction. The correct control there is the CPU's own protection level, which
is enforced in the CPU and not bypassable from the network.

**S7comm classic (S7-300/400)** is genuinely unoccupied and is the natural next
protocol, precisely because those CPUs have no protection level worth the name.

## Testing

```sh
test/run_all.sh --clean
```

Builds, brings up five listeners on their proper ports, runs the unit tests and
three integration suites, and tears everything down on exit. It refuses to start
on top of anything and names what is there instead of just reporting a
collision.

- **`go test ./...`** — 79 tests and three fuzz targets, ~90% of the package,
  clean under `-race`.
- **`test/enforcement_test.py`** — classification and evasion. Writes 0xDEAD
  directly to the device first, to prove the harness can change state before
  claiming the proxy stopped it, then asserts the register is *unchanged* after
  a denied write. That distinction — enforcement versus logging — is the point.
- **`test/response_test.py`** — runs against `rogue_device.py`, a deliberately
  faulty device that selects its misbehaviour from the unit id.
- **`test/policy_test.py`** — two listeners fronting the same device with
  disjoint scopes.
- **`test/identity.py`** — tells you what is actually listening on a port, so a
  misconfigured harness fails with a clear message instead of a confusing one.

## Limitations

Stated plainly, because an inline element in a control path is not a thing to be
vague about.

- **Never run against production hardware.** Everything here is validated
  against simulators, public captures and fuzzing.
- **Not certified.** 62443-4-2 would assess this as an NDR-class component; that
  work has not been done.
- **No TLS**, so no Modbus/TCP Security (port 802).
- **No multiplexing**, no connection pooling, no HA, no management plane.
- **`fail_mode` is a real decision, not a default.** IEC 62443-3-3 SR 5.2 RE 3
  wants fail-close at a zone boundary; SR 7.1/7.2 push the other way. Choose
  deliberately and write down why.

## Related

[ConduitScope](https://github.com/jkobierczynski/ConduitScope) decodes OT
protocols from packet captures and checks them against a zone/conduit policy.
The two are complements: passive discovery finds the conduits that exist, this
enforces the ones that should. They are independent implementations on purpose —
a shared decoder would mean they agree for the wrong reasons.

## A note on how this was built

Written with substantial AI assistance. The protocol analysis, the design
decisions and the reasons for them are documented above and in the source
comments; that reasoning, and the choices about what *not* to build, are the
parts worth reviewing. The function-code table, the traps it encodes and the
scope decisions in [Protocol scope](#protocol-scope) came out of a deliberate
research pass and are the substance of the project.

## License

Apache-2.0.
