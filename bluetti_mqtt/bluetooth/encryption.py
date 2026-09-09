"""
This implements the Bluetti encryption in use around January 2025.

You can tell if a device is using encryption or not via the "manufacturer specific data"
in the BLE advertisement payload (is_device_using_encryption). These new messages all start
with 0x2a2a, so you can also check if you're receiving one of those when you connect.

Brief overview of the encryption handshake:

1) Initialize a temporary key

This key is used to encrypt the intial key exchange. This doesn't do anything
for security beyond obfuscating the communication, as the data you need to
generate the key is in the messages anyone can sniff + static values that you
can from the firmware or existing Bluetti applications.

- Receive a "challenge". Use that value to derive an AES key + IV.
- Answer the challenge by returning the IV
- Receive ok from the device
- Further communication now uses this temporay key (unsecure_aes_key). The IV is
  also static (unsecure_aes_iv)

2) Key exchange

This is standard ECDH. We have the private key for signature freely available in
firmware / Bluetti applications, so vulnerable to MITM. But it also means we can
have this library, so no complaints.

- Peer sends his signed pubkey
- We check the the signature, and send our signed pubkey
- Both the us and the device use these to derive a shared secret
- Peer acknowledges the validity of our key
- Further communication is now encrypted with the shared secret (secure_aes_key)

3) Business as usual

Just encode/decode the messages between the previously existing procol (modbus)
and the bluetooth packets.

--

If you're looking to use this library into another project, you should be able to plumb in
the PassthroughConnection / EncryptedConnection based on the advertisement data and use those
as an extra layer between your existing code and the bluetooth client. Check the comments in
the Connection class for the callbacks used.
"""


import asyncio
import hashlib
import logging
import os
import textwrap
from collections.abc import Callable
from enum import Enum
from typing import Any, Awaitable

import pyasn1.codec.der.decoder as der_decoder
import pyasn1.codec.der.encoder as der_encoder
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pyasn1.type import univ

# This will use the same private key on every run, along with a null IV.
# Helpful if you're working with packet dumps, but leave to False outside of
# testing use-cases.
TESTING_ONLY_NO_RANDOM = False

KEX_MAGIC = b"**"
AES_BLOCK_SIZE = 16


class ConnConstantsV2(Enum):
    LOCAL_AES_KEY = "459FC535808941F17091E0993EE3E93D"


class ECDHUtils(Enum):
    SECP_256R1_PUBLIC_PREFIX = "3059301306072a8648ce3d020106082a8648ce3d03010703420004"


class SignatureCrypt(Enum):
    PRIVATE_KEY_L1 = "4F19A16E3E87BDD9BD24D3E5495B88041511943CBC8B969ADE9641D0F56AF337"
    PUBLIC_KEY_K2 = "3059301306072a8648ce3d020106082a8648ce3d03010703420004A73ABF5D2232C8C1C72E68304343C272495E3A8FD6F30EA96DE2F4B3CE60B251EE21AC667CF8A71E18B46B664EAEFFE3C489F24F695B6411DB7E22CCC85A8594"


class BleConfig(Enum):
    AD_DATA_BLUETTI_ENCRYPTED_HEX = "424c5545545445"
    AD_DATA_BLUETTI_HEX = "424c5545545449"
    ENCRYPTED_ESP32_HEX = "424c5545545446"


def is_device_using_encryption(manufacturer_data):
    return manufacturer_data.get(0x4C42) == bytes.fromhex(
        BleConfig.ENCRYPTED_ESP32_HEX.value
    )


## Crypto helpers - Most of those are specific to what Bluetti is doing


def aes_decrypt(data, aes_key, iv):
    # 0086 3044e63d 05820d1...
    # |    |        |> Cipher text
    # |    |---------> iv seed (if passed, cipher text starts here instead)
    # |--------------> Decrypted text length(uint16, big endian), to remove padding

    data_len = (data[0] << 8) + data[1]
    if iv is None:
        iv = hashlib.md5(data[2:6]).digest()
        encrypted = memoryview(data)[6:]
    else:
        encrypted = memoryview(data[2:])


    if data_len > len(encrypted):
        logging.debug(f"aes_decrypt: incomplete packet wanted {data_len} have {len(encrypted)}")
        return bytes(0)

    if len(encrypted) % AES_BLOCK_SIZE != 0:
        raise ValueError(f"Data not aligned on aes block size {AES_BLOCK_SIZE}, data size {len(encrypted)}, decryped_data_len={data_len}")

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    decrypted = decrypted[:data_len]

    logging.debug(">PLAIN " + decrypted.hex())
    return decrypted


def aes_encrypt(data, aes_key, iv):
    message_header = int.to_bytes(len(data), 2, "big")
    if iv is None:
        iv_seed = os.urandom(4)
        if TESTING_ONLY_NO_RANDOM:
            iv_seed = bytes(4)
        iv = hashlib.md5(iv_seed).digest()
        message_header += iv_seed

    padding = (AES_BLOCK_SIZE - len(data) % AES_BLOCK_SIZE) % AES_BLOCK_SIZE
    data += bytes(padding)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(data) + encryptor.finalize()
    encrypted = message_header + encrypted

    logging.debug("PLAIN> " + data.hex())
    return encrypted


def hexsum(s, sz):
    checksum = sum(s)
    as_hex = f"{checksum:0{sz*2}x}"
    return bytes.fromhex(as_hex)


def hexxor(a, b):
    if len(a) != len(b):
        raise ValueError("Can only XOR two identical length byte strings")
    return bytes([x ^ y for x, y in zip(a, b)])


def pubkey_to_bytes(pubkey):
    out = pubkey.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

    if out[0] != 0x4 or len(out) != 65:
        raise RuntimeError(
            "First byte should be 04 for the uncompressed format, and total size 64"
        )

    return out[1:]


def pubkey_from_bytes(data):
    encoded_peer_pubkey = bytes.fromhex(ECDHUtils.SECP_256R1_PUBLIC_PREFIX.value) + data
    return serialization.load_der_public_key(encoded_peer_pubkey)


def generate_keypair():
    private = ec.generate_private_key(ec.SECP256R1())

    if TESTING_ONLY_NO_RANDOM:
        logging.warning("TESTING MODE, USING WELL-KNOWN KEYS")
        private = serialization.load_pem_private_key(
            textwrap.dedent(
                """
                -----BEGIN EC PRIVATE KEY-----
                MHcCAQEEIHqNGJ2aSB0lbC9a5fNt9UpAZwleU+bc+toVP3iKLARsoAoGCCqGSM49
                AwEHoUQDQgAE9QOdFYukvMMFtW/5P4nADp2RbcUU9uAkllmCa+JtExX4MMQ5WLAZ
                2uULDJkZerY5kqOgmNlWYTLGh5pAfgRHEg==
                -----END EC PRIVATE KEY-----
                """
            ).encode("ascii"),
            password=None,
        )

    return (private.public_key(), private)


def raw_ecdsa_to_der(sig):
    # <byte r[32]> <byte s[32]>

    if len(sig) != 64:
        raise ValueError("ecdsa signature is the wrong size")

    seq = univ.SequenceOf()
    seq.extend(
        [
            univ.Integer(int.from_bytes(sig[:32], "big")),  # r
            univ.Integer(int.from_bytes(sig[32:], "big")),  # s
        ]
    )
    return der_encoder.encode(seq)


def der_to_raw_ecdsa(sig):
    # 30 45 02 20 1956307e59448178b47c222e4e1e6c8ef7d707bc230e5a9fa77f919ec44e5f74
    # |  |  |  |  |> byte r[0x20]
    # |  |  |  |---> Length
    # |  |  |------> DER type (int)
    # |  |---------> Payload size
    # |------------> DER type (sequence)

    #       02 21 00cfad6e11abd5e803fb6874c3838bc968db1f3c070ae6b85db9d8ed8936a1eb5c
    #       |  |  |> byte s[0x21]
    #       |  |---> Length
    #       |------> DER type (int)

    seq, remainder = der_decoder.decode(sig)
    if remainder:
        raise ValueError("Found trailing data")

    return b"".join([int.to_bytes(int(x), 0x20, "big") for x in seq])


def verify_and_extract_signed_data(message, signed_data_suffix):
    # 64 bytes of data
    # 64 bytes of signature
    if len(message) != 128:
        raise ValueError("Unexpected message length")

    data = message[:64]
    signature = message[64:]
    signed_data = data.tobytes() + signed_data_suffix
    der_signature = raw_ecdsa_to_der(signature)
    try:
        key_bytes = bytes.fromhex(SignatureCrypt.PUBLIC_KEY_K2.value)
        serialization.load_der_public_key(key_bytes).verify(
            der_signature, signed_data, ec.ECDSA(hashes.SHA256())
        )
        logging.debug("Signature OK")
    except InvalidSignature:
        raise

    return data


## Protocol


class MessageType(Enum):
    CHALLENGE = 1
    CHALLENGE_ACCEPTED = 3
    PEER_PUBKEY = 4
    PUBKEY_ACCEPTED = 6


class Message:
    """
    Two types of messages. The first one is for communication that happens before we have
    a proper symmetric key available. These are fully handled by this file, it's purely
    to setup the encryption protocol.

    2a2a .... 0000
    |         |> Body checksum
    |    |-----> Body
    |----------> Magic value for pre-key-exchange

    The second type is for anything after. This can either contain the type 1 message above, or
    anything else -- at this point we're just wrapping the regular protocol, and we just forward
    the packets dowm the regular processing path after decrypting them.

    See aes_decrypt() for the format.
    """

    def __init__(self, buffer: bytes):
        self.buffer = buffer
        self.view = memoryview(self.buffer)

    @property
    def header(self) -> memoryview:
        return self.view[:2]

    @property
    def is_pre_key_exchange(self) -> bool:
        return self.header == KEX_MAGIC

    @property
    def checksum(self) -> memoryview:
        return self.view[-2:]

    @property
    def body(self) -> memoryview:
        return self.view[len(self.header) : -len(self.checksum)]

    @property
    def data(self) -> memoryview:
        return self.body[2:]

    @property
    def type(self) -> int:
        return MessageType(self.body[0])

    def verify_checksum(self):
        message_checksum = self.checksum
        computed_checksum = hexsum(self.body, len(message_checksum))
        if computed_checksum != message_checksum:
            raise ValueError("Checksum mismatch")
        logging.debug("Checksum OK")


class Connection:
    def __init__(
        self,
        on_plaintext_packet: Callable[[bytearray], Awaitable[None]],
        write: Callable[[bytes], Awaitable[Any]],
    ):
        """
        - write is what we call when we want to push raw bytes to the connection
        - on_plaintext_packet is what we call when we have fresh (decrypted) data available
        - on_packet is what we expect someone (the owner of the connection) to call
          when new data is available
        """
        self.on_plaintext_packet = on_plaintext_packet
        self.write_raw_packet = write
        self.ready_event = asyncio.Event()

    async def wait_until_ready(self):
        """
        For encrypted connections, we need some time to perform the handshake. Can't use the
        connection before this is done.
        """
        raise NotImplementedError()

    async def on_packet(self, buffer: bytearray) -> None:
        raise NotImplementedError()

    async def write(self, buffer: bytes) -> None:
        """
        Write bytes, maybe encrypting them before
        """
        raise NotImplementedError()


class PassthroughConnection(Connection):
    async def on_packet(self, buffer: bytearray) -> None:
        await self.on_plaintext_packet(buffer)

    async def write(self, buffer: bytes) -> None:
        await self.write_raw_packet(buffer)

    async def wait_until_ready(self):
        return


class EncryptedConnection(Connection):
    # Derived exclusively from data sent over the network
    # Used for the initial handshake
    unsecure_aes_key: bytes | None = None

    # Predictably derived from a seed sent by the peer
    # This is the same for all the messages encrypted
    # with that key during the connection
    unsecure_aes_iv: bytes | None = None

    # Proper key exchange gives us another key,
    # that is used for the remainder of the connection
    # IV is random per message
    secure_aes_key: bytes | None = None

    # Received through key exchange
    # The signing key for the key exchange is well-known
    peer_pubkey: bytes | None = None

    buffer_begin: bytes | None = None


    async def on_packet(self, buffer: bytearray) -> None:
        if self.buffer_begin is None:
            self.buffer_begin = bytes(0)
        if len(self.buffer_begin) > 0:
            logging.debug(f"on_packet: {len(self.buffer_begin)} from previos packet")
            message = Message(self.buffer_begin + buffer)
            self.buffer_begin = bytes(0)
        else:
            message = Message(buffer)
        if message.is_pre_key_exchange:
            message.verify_checksum()
            if message.type == MessageType.CHALLENGE:
                return await self.msg_challenge(message)
            if message.type == MessageType.CHALLENGE_ACCEPTED:
                return await self.msg_challenge_accepted(message)
            else:
                raise ValueError(f"Unknown message type {message.type}")

        if self.unsecure_aes_key is None:
            raise ValueError("Received encrypted message before key initialization")

        key, iv = (
            (self.unsecure_aes_key, self.unsecure_aes_iv)
            if self.secure_aes_key is None
            else (self.secure_aes_key, None)
        )
        decrypted_buf = aes_decrypt(message.buffer, key, iv)
        if len(decrypted_buf) <= 0:
                self.buffer_begin = message.buffer

        decrypted = Message(decrypted_buf)

        if decrypted.is_pre_key_exchange:
            decrypted.verify_checksum()
            if decrypted.type == MessageType.PEER_PUBKEY:
                return await self.msg_peer_pubkey(decrypted)
            if decrypted.type == MessageType.PUBKEY_ACCEPTED:
                return await self.msg_key_accepted(decrypted)

        await self.on_plaintext_packet(decrypted.buffer)

    async def write(self, buffer: bytes) -> None:
        if self.secure_aes_key is None:
            raise RuntimeError("Encryption handshake not finished yet")

        encrypted = aes_encrypt(buffer, self.secure_aes_key, None)
        await self.write_raw_packet(encrypted)

    async def wait_until_ready(self):
        await self.ready_event.wait()

    async def msg_challenge(self, message: Message) -> None:
        logging.debug("Received challenge")

        if len(message.data) != 4:
            raise ValueError("Unexpected message length")
        self.unsecure_aes_iv = hashlib.md5(message.data[::-1].tobytes()).digest()
        static_key = bytes.fromhex(ConnConstantsV2.LOCAL_AES_KEY.value)
        self.unsecure_aes_key = hexxor(self.unsecure_aes_iv, static_key)

        logging.info("Unsecure iv  " + self.unsecure_aes_iv.hex())
        logging.info("Unsecure key " + self.unsecure_aes_key.hex())

        body = bytes.fromhex("0204") + self.unsecure_aes_iv[8:12]
        await self.write_raw_packet(b"".join([KEX_MAGIC, body, hexsum(body, 2)]))

    async def msg_challenge_accepted(self, message: Message) -> None:
        logging.debug("Received challenge success confirmation")

        if len(message.data) != 1:
            raise ValueError("Unexpected message length")
        if message.data[0] != 0:
            raise ValueError("Challenge response is not 0")

    async def msg_peer_pubkey(self, message: Message) -> None:
        logging.debug("Received peer pubkey, checking signature")
        data = verify_and_extract_signed_data(message.data, self.unsecure_aes_iv)
        self.peer_pubkey = pubkey_from_bytes(data)

        logging.debug("Generating a local keypair")
        self.my_pubkey, self.my_privkey = generate_keypair()
        my_pubkey_bytes = pubkey_to_bytes(self.my_pubkey)

        logging.debug("Signing the local pubkey")
        signing_secret = int.from_bytes(
            bytes.fromhex(SignatureCrypt.PRIVATE_KEY_L1.value), "big"
        )
        signing_key = ec.derive_private_key(signing_secret, ec.SECP256R1())
        to_sign = my_pubkey_bytes + self.unsecure_aes_iv
        signature = signing_key.sign(to_sign, ec.ECDSA(hashes.SHA256()))
        raw_signature = der_to_raw_ecdsa(signature)

        body = b"".join([bytes.fromhex("0580"), my_pubkey_bytes, raw_signature])
        msg = b"".join([KEX_MAGIC, body, hexsum(body, 2)])
        encrypted_msg = aes_encrypt(msg, self.unsecure_aes_key, self.unsecure_aes_iv)
        await self.write_raw_packet(encrypted_msg)

    async def msg_key_accepted(self, message: Message) -> None:
        logging.debug("Received key exchange confirmation, calculating shared secret")

        if len(message.data) != 1:
            raise ValueError("Unexpected message length")
        if message.data[0] != 0:
            raise ValueError("Key acceptance response is not 0")

        self.secure_aes_key = self.my_privkey.exchange(ec.ECDH(), self.peer_pubkey)
        logging.info("Secure key   " + self.secure_aes_key.hex())

        self.ready_event.set()


## The encapsulated messages look like this, check out other bluetti libraries for parsing

# 01 ?? ?? ?? ........ ?? ??
# |  |  |     |        |---> Modbus CRC16 (2 bytes)
# |  |  |     |------------> data
# |  |  |------------------> register address (2 bytes)
# |  |---------------------> function code
# |------------------------> modbus slave address (always 1)
