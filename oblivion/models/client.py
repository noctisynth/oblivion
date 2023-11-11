from typing import Tuple
from multilogging import multilogger
from loguru import logger

from ..utils.parser import length, Oblivion, OblivionPath
from ..utils.generator import generate_key_pair
from .. import exceptions
from .packet import OSC, OKE, OED

import socket
import json

logger = multilogger(name="Oblivion", payload="models.client")
""" `models.client`日志 """


class Response:
    header: str
    content: bytes
    olps: str
    status_code: int

    def __eq__(self, __response: "Response") -> bool:
        return (
            __response.header == self.header
            and __response.content == self.content
            and __response.olps.rstrip("/") == self.olps.rstrip("/")
            and __response.status_code == self.status_code
        )

    def __bool__(self) -> bool:
        return self.ok

    def __bytes__(self) -> bytes:
        return self.content

    def __repr__(self) -> str:
        return f"<Response [{self.status_code}]>"

    def __str__(self) -> str:
        return self.text

    @property
    def ok(self) -> bool:
        return self.status_code < 400

    @property
    def text(self):
        return self.content.decode()

    def json(self):
        return json.loads(self.content)


class Request:
    def __init__(
        self,
        method: str = None,
        olps: str = None,
        data: dict = None,
        file: bytes = None,
        key_pair: Tuple[bytes, bytes] = None,
        verify: bool = True,
        tfo: bool = True,
    ) -> None:
        self.method = method.upper()
        self.path = OblivionPath(olps)
        self.olps = self.path.olps
        self.oblivion = Oblivion(method=method, olps=self.olps)
        self.plain_text = self.oblivion.plain_text
        self.data = data
        self.file = file
        self.key_pair = key_pair
        self.verify = verify
        self.tfo = tfo
        self.prepared = False

    def __repr__(self) -> str:
        return f"<Request [{self.method}] {self.olps}>"

    def prepare(self) -> None:
        self.private_key, self.public_key = (
            self.key_pair if self.key_pair else generate_key_pair()
        )

        try:
            self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.tfo:
                self.tcp.setsockopt(socket.SOL_TCP, socket.TCP_FASTOPEN, 5)
            self.tcp.settimeout(20)
            self.tcp.connect((self.path.host, self.path.port))
        except ConnectionRefusedError:
            raise exceptions.ConnectionRefusedError("向服务端的链接请求被拒绝, 可能是由于服务端遭到攻击.")

        self.send_header()

        oke = OKE(PRIVATE_KEY=self.private_key).from_public_key_bytes(self.public_key)
        self.aes_key = oke.from_stream_with_salt(self.tcp).SHARED_AES_KEY
        oke.to_stream(self.tcp)

        self.prepared = True

    def send_header(self) -> None:
        header = self.plain_text.encode()
        self.tcp.sendall(length(header))
        self.tcp.sendall(header)

    def send(self) -> None:
        if self.method == "POST":
            if isinstance(self.data, (dict, list)):
                oed = OED(AES_KEY=self.aes_key).from_dict(self.data)
            elif not self.data:
                oed = OED(AES_KEY=self.aes_key).from_dict({})
            else:
                raise ValueError("POST data must be dict!")
        elif self.method == "PUT":
            if isinstance(self.data, (dict, list)):
                OED(AES_KEY=self.aes_key).from_dict(self.data).to_stream(self.tcp, 5)
            elif not self.data:
                OED(AES_KEY=self.aes_key).from_dict({}).to_stream(self.tcp, 5)
            else:
                raise ValueError("PUT data must be dict!")

            if isinstance(self.file, (bytes, bytearray)):
                oed = OED(AES_KEY=self.aes_key).from_bytes(self.file)
            elif not self.file:
                oed = OED(AES_KEY=self.aes_key).from_bytes(b"")
            else:
                raise ValueError("PUT file must be bytes, not others!")
        elif self.method == "GET":
            return
        else:
            raise exceptions.UnsupportedMethod

        oed.to_stream(self.tcp, 5)

    def recv(self) -> Response:
        if not self.prepared:
            raise NotImplementedError

        oed = OED(AES_KEY=self.aes_key).from_stream(self.tcp, 5, verify=self.verify)
        response = Response()
        response.header = self.plain_text
        response.content = oed.DATA
        response.olps = self.olps
        response.status_code = OSC().from_stream(self.tcp).STATUS_CODE
        return response
