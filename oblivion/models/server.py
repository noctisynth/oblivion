from multilogging import multilogger
from typing import Tuple, NoReturn, Callable, Any
from concurrent.futures import ThreadPoolExecutor

from ._models import BaseConnection, BaseHook
from .render import BaseResponse, TextResponse
from .packet import OSC, OKE, OED

from .. import exceptions

from ..utils.parser import OblivionRequest
from ..utils.generator import generate_key_pair

import socket
import os
import traceback
import json
import sys


logger = multilogger(name="Oblivion", payload="models")
""" `models.server`日志 """


class ServerConnection(BaseConnection):
    def __init__(self, key_pair: Tuple[bytes, bytes]) -> None:
        self.private_key, self.public_key = key_pair

    def handshake(self, stream: socket.socket, client_address: Tuple[str, int]) -> None:
        self.request = OblivionRequest(stream.recv(int(stream.recv(4).decode())).decode())  # 接收请求头
        self.request.remote_addr, self.request.remote_port = client_address

        oke = OKE(PRIVATE_KEY=self.private_key, PUBLIC_KEY=self.public_key).new()
        oke.to_stream_with_salt(stream)
        self.aes_key = oke.from_stream(stream).SHARED_AES_KEY

        if self.request.method == "POST":
            self.request.POST = json.loads(
                OED(AES_KEY=self.aes_key).from_stream(stream, 5).DATA
            )
            self.request.PUT = None
        elif self.request.method == "GET":
            self.request.POST = {}
            self.request.PUT = None
        elif self.request.method == "PUT":
            self.request.POST = json.loads(
                OED(AES_KEY=self.aes_key).from_stream(stream, 5).DATA
            )
            self.request.PUT = OED(AES_KEY=self.aes_key).from_stream(stream, 5).DATA
        else:
            raise exceptions.UnsupportedMethod(self.request.method)

    def solve(self, stream: socket.socket, address: Tuple[str, int]) -> OblivionRequest:
        self.handshake(stream, address)
        return self.request


class Hook(BaseHook):
    def __init__(
        self,
        olps: str,
        res: str = "",
        handle: Callable[..., Any] = None,
        method: str = "GET",
    ) -> None:
        super().__init__(olps, res, handle, method)

    def response(
        self, tcp: socket.socket, request: OblivionRequest, aes_key: bytes
    ) -> int:
        if callable(self.res):
            callback: BaseResponse = self.res(request)
        else:
            callback: BaseResponse = self.res

        OED(AES_KEY=aes_key, STATUS_CODE=callback.status_code).from_bytes(
            bytes(callback)
        ).to_stream(tcp, 5)
        OSC().from_int(callback.status_code).to_stream(tcp)
        return callback.status_code


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
        host: str = "0.0.0.0",
        port: int = 80,
        max_connection: int = 1024,
        hooks: Hooks = [],
        not_found: str | Callable = "404 Not Found",
        tfo: bool = True,
    ) -> None:
        self.host = host
        self.port = port
        self.max_connections = max_connection
        self.hooks: Hooks = tuple(hooks)
        self.not_found = (
            Hook("/404", res=not_found)
            if callable(not_found)
            else Hook("/404", res=TextResponse(not_found))
        )
        self.threadpool = ThreadPoolExecutor(max_workers=os.cpu_count() * 3)
        self.tfo = tfo

    def _handle(self, __stream: socket.socket, __address: Tuple[str, int]) -> None:
        __stream.settimeout(20)
        connection = ServerConnection(generate_key_pair())
        request = connection.solve(__stream, __address)

        for hook in self.hooks:
            if hook.is_valid_header(request):
                status_code = hook.response(__stream, request, connection.aes_key)
                __stream.close()
                print(
                    f"{request.protocol}/{request.version} {request.method} From {__address[0]} {request.olps} {status_code}"
                )
                return

        self.not_found.response(__stream, request, connection.aes_key)
        __stream.close()
        print(
            f"{request.protocol}/{request.version} {request.method} From {__address[0]} {request.olps} 404"
        )

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
        if self.tfo:
            tcp.setsockopt(socket.SOL_TCP, socket.TCP_FASTOPEN, 5)

        print(f"Starting server at Oblivion://{self.host}:{self.port}/")
        print("Quit the server by CTRL-BREAK.")

        while True:
            try:
                stream, address = tcp.accept()  # 等待客户端连接
                self.threadpool.submit(self.handle, stream, address)
            except KeyboardInterrupt:
                self.threadpool.shutdown(False)
                tcp.close()
                sys.exit()
