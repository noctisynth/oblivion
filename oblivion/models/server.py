from multilogging import multilogger
from typing import Tuple, NoReturn, Callable, Any
from concurrent.futures import ThreadPoolExecutor

from ._models import BaseConnection, BaseHook
from .packet import OKE, OED

from .. import exceptions

from ..utils.parser import OblivionRequest
from ..utils.generator import generate_key_pair

import socket
import os
import traceback
import json


logger = multilogger(name="Oblivion", payload="models")
""" `models.server`日志 """


class ServerConnection(BaseConnection):
    def __init__(self, key_pair: Tuple[bytes, bytes]) -> None:
        self.private_key, self.public_key = key_pair

    def handshake(self, stream: socket.socket, client_address: Tuple[str, int]) -> None:
        len_header = int(stream.recv(4).decode())
        self.request = OblivionRequest(stream.recv(len_header).decode())  # 接收请求头
        self.request.remote_addr = client_address[0]
        self.request.remote_port = client_address[1]

        oke = (
            OKE(PRIVATE_KEY=self.private_key)
            .new()
            .from_public_key_bytes(self.public_key)
        )
        oke.to_stream_with_salt(stream)
        self.aes_key = oke.from_stream(stream).SHARED_AES_KEY

        if self.request.method == "POST":
            self.request.POST = json.loads(
                OED(AES_KEY=self.aes_key).from_stream(stream, 5).DATA
            )
        elif self.request.method == "GET":
            self.request.POST = None
        else:
            pass

    def solve(self, client, client_address) -> OblivionRequest:
        self.handshake(client, client_address)
        return self.request


class Hook(BaseHook):
    def __init__(
        self, olps: str, res: str = "", handle: Callable[..., Any] = None, method="GET"
    ) -> None:
        super().__init__(olps, res, handle, method)

    def response(
        self, tcp: socket.socket, request: OblivionRequest, aes_key: bytes
    ) -> None:
        if callable(self.res):
            plaintext = self.res(request)
        else:
            plaintext = self.res

        OED(AES_KEY=aes_key).from_json_or_string(plaintext).to_stream(tcp, 5)


class Hooks(list[Hook]):
    def __init__(self, *args, **kwargs) -> None:
        super(Hooks, self).__init__(*args, **kwargs)

    def get(self, olps: str) -> Hook | None:
        for hook in self:
            if hook.is_valid(olps):
                return hook

    def remove(self, olps: str) -> None:
        for hook in self:
            if hook.is_valid(olps):
                return super().remove(hook)

    def add(self, olps: str, res: str | Callable) -> bool:
        for hook in self:
            if hook.is_valid(olps):
                print(f"Warning: A hook with {olps} exists, will do nothing here.")
                return False

        self.append(Hook(olps=olps, res=res, method="GET"))
        return True

    def edit(self, olps: str, res: str | Callable) -> bool:
        for index, hook in enumerate(self):
            if hook.is_valid(olps):
                self.insert(index, res)
                return True

        return False

    def regist(self, olps: str) -> Callable:
        def wrapper(func):
            self.add(olps, func)

        return wrapper


class Server:
    def __init__(
        self,
        host="0.0.0.0",
        port=80,
        max_connection=1024,
        hooks=[],
        not_found="404 Not Found",
    ) -> None:
        self.host = host
        self.port = port
        self.max_connections = max_connection
        self.hooks: Hooks = tuple(hooks)
        self.not_found = Hook("/404", res=not_found)
        self.threadpool = ThreadPoolExecutor(max_workers=os.cpu_count() * 3)

    def _handle(self, __stream: socket.socket, __address: Tuple[str, int]) -> None:
        __stream.settimeout(20)
        connection = ServerConnection(generate_key_pair())
        request = connection.solve(__stream, __address)

        for hook in self.hooks:
            logger.debug(f"Checking Hook: {hook.olps}")
            if hook.is_valid_header(request):
                hook.response(__stream, request, connection.aes_key)
                print(
                    f"{request.protocol}/{request.version} {request.method} From {__address[0]} {hook.olps} 200"
                )
                break

        if hook.is_valid_header(request):
            return

        self.not_found.response(__stream, connection.aes_key)
        __stream.close()
        print(f"Oblivion/1.0 From {__address} {hook.olps} 404")

    def handle(self, __stream: socket.socket, __address: Tuple[str, int]):
        try:
            self._handle(__stream, __address)
        except:
            traceback.print_exc()

    def run(self) -> NoReturn:
        print("Performing system checks...\n")
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            tcp.bind((self.host, self.port))
        except:
            raise exceptions.AddressAlreadyInUse
        tcp.listen(self.max_connections)
        tcp.setsockopt(socket.SOL_TCP, socket.TCP_FASTOPEN, 5)
        print(f"Starting server at Oblivion://{self.host}:{self.port}/")
        print("Quit the server by CTRL-BREAK.")

        while True:
            stream, address = tcp.accept()  # 等待客户端连接
            self.threadpool.submit(self.handle, stream, address)
