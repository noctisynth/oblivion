from typing import Tuple
from multilogging import multilogger
from loguru import logger

from ..utils.parser import length
from ..utils.generator import generate_key_pair, generate_aes_key

from .. import exceptions
from ._models import BaseRequest
from .packet import OPK, OEA, OED

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
            OEA(PUBLIC_KEY=OPK().from_stream(self.tcp).PUBLIC_KEY).from_aes_key(self.aes_key).to_stream(self.tcp)
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

        OPK().from_public_key_bytes(self.public_key).to_stream(self.tcp)
        return (
            OED(AES_KEY=OEA(PRIVATE_KEY=self.private_key).from_stream(self.tcp).AES_KEY)
            .from_stream(self.tcp, 5, verify=self.verify)
            .DATA
        )
