#!/usr/bin/env python3

import argparse
import asyncio
import sys

from bluetti_mqtt.bluetooth import BluetoothClient, ModbusError
from bluetti_mqtt.core import ReadHoldingRegisters


def bytes_to_displayable(buffer):
    output = []
    for ascii_code in buffer:
        if 32 <= ascii_code <= 126:
            output.append(chr(ascii_code))
        else:
            output.append(".")
    return "".join(output)


async def read_address(client, address, size):
    command = ReadHoldingRegisters(address, size)
    response_future = await client.perform(command)
    try:
        response = await response_future
        return (response, command.parse_response(response))
    except ModbusError:
        raise
    except BaseException:
        raise


async def main(args):
    client = BluetoothClient(args.address, args.encrypted)
    asyncio.get_running_loop().create_task(client.run())

    while not client.is_ready:
        print("Waiting for connection...")
        await asyncio.sleep(1)
        continue

    print("Ready.")

    while True:
        print("[address] (length)>> ", end="")
        sys.stdout.flush()

        entry = input().strip().split(" ", 1)
        address = int(entry[0])
        size = 1

        data = None

        if len(entry) > 1:
            size = int(entry[1])
            try:
                raw_data, data = await read_address(client, address, size)
                size += 1
            except BaseException as e:
                print(repr(e))
        else:
            for size in range(1, 100):
                try:
                    raw_data, data = await read_address(client, address, size)
                except BaseException:
                    break

        if data is None:
            print("<err>")
        else:
            print(
                f"[{size-1:2}|{len(data):2}] | {data.hex()} | {bytes_to_displayable(data)}"
            )
            print(f"    {raw_data.hex()} | {bytes_to_displayable(raw_data)}")

        sys.stdout.flush()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--encrypted",
        action="store_true",
        help="Turn on encryption (refer to the scan output)",
    )
    parser.add_argument("-v", action="store_true", help="Verbose output")
    parser.add_argument(
        "address", metavar="ADDRESS", help="The device MAC to connect to for discovery"
    )

    asyncio.run(main(parser.parse_args()))
