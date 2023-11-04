from typing import Tuple
from multilogging import multilogger
from loguru import logger

from ..utils.parser import length
from ..utils.encryptor import encrypt_aes_key
from ..utils.decryptor import decrypt_aes_key
from ..utils.generator import generate_key_pair, generate_aes_key

from .. import exceptions
from ._models import BaseRequest
from .packet import OEA, OED

import socket


logger = multilogger(name="Oblivion", payload="models.client")
""" `models.client`日志 """


class Request(BaseRequest):
    def __init__(
        self,
        method: str = None,
        olps: str = None,
        data: dict = None,
        key_pair: Tuple[bytes, bytes] = None,
        verify: bool = True,
    ) -> None:
        super().__init__(method, olps, data, key_pair, verify)

    def __repr__(self) -> str:
        return f"<Request [{self.method}] {self.olps}>"

    def prepare(self) -> None:
        self.aes_key = generate_aes_key()  # 生成随机的AES密钥
        self.private_key, self.public_key = (
            self.key_pair if self.key_pair else generate_key_pair()
        )

        try:
            self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp.settimeout(20)
            self.tcp.connect((self.path.host, self.path.port))
        except ConnectionRefusedError:
            raise exceptions.ConnectionRefusedError("向服务端的链接请求被拒绝, 可能是由于服务端遭到攻击.")

        self.send_header()
        if self.method == "POST":
            len_server_public_key = int(self.tcp.recv(4).decode())  # 接收公钥长度
            server_public_key = self.tcp.recv(len_server_public_key)  # 接收公钥
            logger.debug(f"接收到的公钥: {server_public_key.decode()}")

            encrypted_aes_key = encrypt_aes_key(
                self.aes_key, server_public_key
            )  # 使用RSA公钥加密AES密钥
            self.tcp.sendall(length(encrypted_aes_key))  # 发送AES_KEY长度
            self.tcp.sendall(encrypted_aes_key)  # 发送AES_KEY
        elif self.method == "GET":
            pass
        elif self.method == "FORWARD":
            raise NotImplementedError
        else:
            raise NotImplementedError

        self.prepared = True

    def send_header(self) -> None:
        header = self.plain_text.encode()
        self.tcp.sendall(length(header))
        self.tcp.sendall(header)

    def send(self) -> None:
        if self.method == "GET":
            return

        oed = (
            OED(AES_KEY=self.aes_key).from_dict(self.data)
            if self.data
            else OED(AES_KEY=self.aes_key).from_json_or_string("{}")
        )
        oed.to_stream(self.tcp, 5)

    def recv(self) -> str:
        if not self.prepared:
            raise NotImplementedError

        self.tcp.sendall(length(self.public_key))  # 发送本地公钥长度
        self.tcp.sendall(self.public_key)  # 发送本地公钥

        len_encrypted_aes_key = int(self.tcp.recv(4).decode())  # 捕获AES_KEY长度
        encrypted_aes_key = self.tcp.recv(len_encrypted_aes_key)  # 捕获AES_KEY
        decrypted_aes_key = decrypt_aes_key(
            encrypted_aes_key, self.private_key
        )  # 使用RSA私钥解密AES密钥

        return (
            OED(AES_KEY=decrypted_aes_key)
            .from_stream(self.tcp, 5, verify=self.verify)
            .DATA
        )
