from typing import SupportsInt
from socket import socket
from loguru import logger

from .. import exceptions

from ..utils.generator import generate_shared_key, generate_random_salt
from ..utils.encryptor import encrypt_message, encrypt_data
from ..utils.decryptor import decrypt_message
from ..utils.parser import length

from ._models import BasePackage

import json
import random


class ACK(BasePackage):
    """Oblivious Acknowledge"""

    sequence: str

    def __eq__(self, __value: object) -> bool:
        if isinstance(__value, ACK):
            return self.sequence == __value.sequence
        elif isinstance(__value, (bytes, bytearray)):
            return __value == self.plain_data
        else:
            return self.sequence == __value

    def new(self):
        self.sequence = str(random.randint(1000, 9999))
        return self

    def from_stream(self, __stream: socket) -> "ACK":
        self.sequence = __stream.recv(4).decode()
        return self

    def to_stream(self, __stream: socket):
        __stream.send(self.plain_data)

    @property
    def plain_data(self) -> bytes:
        return self.sequence.encode()


class OSC(BasePackage):
    """Oblivious Status Code"""

    STATUS_CODE: int

    def from_int(self, __status_code: int) -> "OSC":
        self.STATUS_CODE = __status_code
        return self

    def from_stream(self, __stream: socket) -> "OSC":
        self.STATUS_CODE = int(__stream.recv(3).decode())
        return self

    def to_stream(self, __stream: socket) -> "OSC":
        __stream.send(self.plain_data)

    @property
    def plain_data(self) -> bytes:
        return str(self.STATUS_CODE).encode()


class OKE(BasePackage):
    """Oblivious Key Exchange"""

    length: int
    PUBLIC_KEY: bytes
    PRIVATE_KEY: bytes
    SALT: bytes
    REMOTE_PUBLIC_KEY: bytes
    SHARED_AES_KEY: bytes

    def new(self) -> "OKE":
        self.SALT = generate_random_salt()
        return self

    def from_public_key_bytes(self, __public_key_bytes: bytes) -> "OKE":
        self.PUBLIC_KEY = __public_key_bytes
        return self

    def from_stream(self, __stream: socket) -> "OKE":
        self.REMOTE_PUBLIC_KEY = __stream.recv(int(__stream.recv(4).decode()))
        self.SHARED_AES_KEY = generate_shared_key(
            self.PRIVATE_KEY, self.REMOTE_PUBLIC_KEY, self.SALT
        )
        return self

    def from_stream_with_salt(self, __stream: socket) -> "OKE":
        self.REMOTE_PUBLIC_KEY = __stream.recv(int(__stream.recv(4).decode()))
        self.SALT = __stream.recv(int(__stream.recv(4).decode()))
        self.SHARED_AES_KEY = generate_shared_key(
            self.PRIVATE_KEY, self.REMOTE_PUBLIC_KEY, self.SALT
        )
        return self

    def to_stream(self, __stream: socket):
        __stream.send(self.plain_data)

    def to_stream_with_salt(self, __stream: socket):
        __stream.send(self.plain_data)
        __stream.send(self.plain_salt)

    @property
    def plain_data(self) -> bytes:
        return length(self.PUBLIC_KEY) + self.PUBLIC_KEY

    @property
    def plain_salt(self) -> bytes:
        return length(self.SALT) + self.SALT


class OED(BasePackage):
    """Oblivious Encrypted Data"""

    length: int
    AES_KEY: bytes
    DATA: str | bytes
    ENCRYPTED_DATA: bytes
    TAG: bytes
    NONCE: bytes
    plain_data: bytes

    def from_json_or_string(self, __json_or_str: str) -> "OED":
        self.ENCRYPTED_DATA, self.TAG, self.NONCE = encrypt_message(
            __json_or_str, self.AES_KEY
        )
        return self

    def from_dict(self, __dict: dict) -> "OED":
        self.DATA = __dict
        self.ENCRYPTED_DATA, self.TAG, self.NONCE = encrypt_message(
            json.dumps(__dict), self.AES_KEY
        )
        return self

    def from_encrypted_data(self, __data: bytes) -> "OED":
        self.ENCRYPTED_DATA = __data
        return self

    def from_bytes(self, __bytes: bytes) -> "OED":
        self.ENCRYPTED_DATA, self.TAG, self.NONCE = encrypt_data(__bytes, self.AES_KEY)
        return self

    def from_stream(
        self, __stream: socket, __attemps: SupportsInt, verify: bool = True
    ) -> "OED":
        attemp = 0
        ack = False
        while attemp < __attemps:
            ack_packet = ACK().from_stream(__stream)  # 捕获ACK数据包

            len_ciphertext = int(__stream.recv(4).decode())  # 捕获加密数据长度
            len_nonce = int(__stream.recv(4).decode())  # 捕获nonce长度
            len_tag = int(__stream.recv(4).decode())  # 捕获tag长度

            self.ENCRYPTED_DATA = __stream.recv(len_ciphertext)  # 捕获加密数据
            self.NONCE = __stream.recv(len_nonce)  # 捕获nonce
            self.TAG = __stream.recv(len_tag)  # 捕获tag

            try:
                self.DATA = decrypt_message(
                    self.ENCRYPTED_DATA,
                    self.TAG,
                    self.AES_KEY,
                    self.NONCE,
                    verify=verify,
                )  # 尝试解密
                __stream.send(ack_packet.plain_data)  # 发送ACK校验包
                ack = True
                break
            except Exception as e:
                logger.warning(f"An error occured: {e}\nRetried {attemp} times.")
                __stream.send(b"0000")
                attemp += 1
                continue
        if not ack:
            __stream.close()
            raise exceptions.AllAttemptsRetryFailed
        return self

    def to_stream(self, __stream: socket, __attemps: SupportsInt):
        attemp = 0
        ack = False
        while attemp <= __attemps:
            ack_packet = ACK().new()
            ack_packet.to_stream(__stream)
            __stream.send(self.plain_data)
            if __stream.recv(4) == ack_packet:
                ack = True
                break
            attemp += 1
        if not ack:
            __stream.close()
            raise exceptions.AllAttemptsRetryFailed

    @property
    def plain_data(self) -> bytes:
        return (
            length(self.ENCRYPTED_DATA)
            + length(self.NONCE)
            + length(self.TAG)
            + self.ENCRYPTED_DATA
            + self.NONCE
            + self.TAG
        )
