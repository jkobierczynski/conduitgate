#!/usr/bin/env python3
"""A simulated Modbus/TCP device, standing in for a PLC.

This is the target conduitgate protects during integration tests. It is a real
Modbus server with a real register file, so a write that reaches it actually
changes state — which is what makes the enforcement assertions meaningful
rather than decorative.

    pip install pymodbus
    python3 test/plcsim.py [port]
"""
import sys

from pymodbus.datastore import ModbusSequentialDataBlock, ModbusServerContext
from pymodbus.server import StartTcpServer

try:  # pymodbus renamed this class across 3.x releases
    from pymodbus.datastore import ModbusDeviceContext as DeviceContext
except ImportError:  # pragma: no cover
    from pymodbus.datastore import ModbusSlaveContext as DeviceContext


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5020

    device = DeviceContext(
        # pymodbus 3.15 offsets the block by one internally, so the first
        # legal start address is 1, not 0.
        di=ModbusSequentialDataBlock(1, [1] * 100),
        co=ModbusSequentialDataBlock(1, [0] * 100),
        hr=ModbusSequentialDataBlock(1, list(range(1000, 1100))),
        ir=ModbusSequentialDataBlock(1, [7] * 100),
    )
    try:
        context = ModbusServerContext(devices=device, single=True)
    except TypeError:  # pragma: no cover - older keyword
        context = ModbusServerContext(slaves=device, single=True)

    print(f"plcsim listening on 127.0.0.1:{port}", flush=True)
    StartTcpServer(context=context, address=("127.0.0.1", port))


if __name__ == "__main__":
    main()
