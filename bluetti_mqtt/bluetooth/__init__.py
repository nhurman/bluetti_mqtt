import logging
import re
from typing import Set
from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bluetti_mqtt.core import BluettiDevice, V2Device, AC200M, AC300, AC500, AC60, EP500, EP500P, EP600, EB3A, AC240P
from .client import BluetoothClient
from .exc import BadConnectionError, ModbusError, ParseError
from .manager import MultiDeviceManager
from bluetti_mqtt.bluetooth.encryption import is_device_using_encryption


DEVICE_NAME_RE = re.compile(r'^(AC180|AC180P|AC200M|AC300|AC500|AC60|EP500P|EP500|EP600|EB3A|AC240P)*(\d+)$')


async def scan_devices():
    print('Scanning....')
    devices = await BleakScanner.discover(return_adv=True)
    if len(devices) == 0:
        print('0 devices found - something probably went wrong')
    else:
        for d, adv in devices.values():
            if d.name and DEVICE_NAME_RE.match(d.name):
                encrypted = is_device_using_encryption(adv.manufacturer_data)
                enc = ' (bluetti, encrypted)' if encrypted else ''
                print(f'Found {d.name}: address {d.address}{enc}')


def build_device(address: str, name: str):
    print(f'matching {name}')
    match = DEVICE_NAME_RE.match(name)
    print(f'match: {match}')
    if match[1] == 'AC180':
        return V2Device(address, match[2], 'AC180')
    if match[1] == 'AC180P':
        return V2Device(address, match[2], 'AC180P')
    if match[1] == 'AC200M':
        return AC200M(address, match[2])
    if match[1] == 'AC240P':
        return AC240P(address, match[2])
    if match[1] == 'AC300':
        return AC300(address, match[2])
    if match[1] == 'AC500':
        return AC500(address, match[2])
    if match[1] == 'AC60':
        return AC60(address, match[2])
    if match[1] == 'EP500':
        return EP500(address, match[2])
    if match[1] == 'EP500P':
        return EP500P(address, match[2])
    if match[1] == 'EP600':
        return EP600(address, match[2])
    if match[1] == 'EB3A':
        return EB3A(address, match[2])


async def check_addresses(addresses: Set[str]):
    logging.debug(f'Checking we can connect: {addresses}')
    devices = await BleakScanner.discover(return_adv=True)
    filtered = [d for d in devices.values() if d[0].address in addresses]
    logging.debug(f'Found devices: {filtered}')

    if len(filtered) != len(addresses):
        return []

    return [build_device(d.address, d.name) for d, adv in filtered]
