from ..utils.encryptor import encrypt_aes_key, encrypt_message
from ..utils.parser import length
from ._models import OblivionPackage

import json


class OEA(OblivionPackage):
    """Oblivous Encrypted AES-Key"""

    length: int
    ENCRYPTED_AES_KEY: bytes

    def from_aes_key(self, __aes_key, __public_key) -> "OEA":
        self.ENCRYPTED_AES_KEY = encrypt_aes_key(__aes_key, __public_key)
        self.length = length(self.ENCRYPTED_AES_KEY)
        return self

    def from_encrypted_aes_key(self, __encrypted_aes_key) -> "OEA":
        self.ENCRYPTED_AES_KEY = __encrypted_aes_key
        self.length = length(self.ENCRYPTED_AES_KEY)
        return self

    @property
    def plain_data(self) -> bytes:
        return self.length + self.ENCRYPTED_AES_KEY


class OED(OblivionPackage):
    """Oblivous Encrypted Data"""

    length: int
    AES_KEY: bytes
    DATA: bytes
    TAG: bytes
    NONCE: bytes
    plain_data: bytes

    def from_json_or_string(self, __json_or_str: str) -> "OED":
        self.DATA, self.TAG, self.NONCE = encrypt_message(__json_or_str, self.AES_KEY)
        return self

    def from_dict(self, __dict: dict) -> "OED":
        self.DATA, self.TAG, self.NONCE = encrypt_message(json.dumps(__dict), self.AES_KEY)
        return self

    def from_encrypted_data(self, __data: bytes) -> "OED":
        self.DATA = __data
        return self

    @property
    def plain_data(self) -> bytes:
        return (
            length(self.DATA)
            + self.DATA
            + length(self.NONCE)
            + self.NONCE
            + length(self.TAG)
            + self.TAG
        )
