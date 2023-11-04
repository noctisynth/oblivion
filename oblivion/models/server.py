from multilogging import multilogger
from typing import Tuple, NoReturn, Callable, Any
from concurrent.futures import ThreadPoolExecutor
from threading import Thread

from ._models import BaseConnection, BaseHook
from .packet import OEA, OED

from ..utils.parser import OblivionRequest, length
from ..utils.encryptor import encrypt_aes_key
from ..utils.decryptor import decrypt_aes_key
from ..utils.generator import generate_key_pair, generate_aes_key

import socket
import queue
import os

logger = multilogger(name="Oblivion", payload="models")
""" `models.server`日志 """


class RSAKeyPairPool:
    pairs: queue.Queue = queue.Queue()

    def new(self):
        key_pair = generate_key_pair()
        for _ in range(5):
            self.pairs.put(key_pair)

    def get(self):
        while True:
            if not self.pairs.empty():
                return self.pairs.get()

    def keep_forever(self, limit: int):
        while True:
            if self.pairs.qsize() < limit * 5:
                self.new()

    def size(self):
        return self.pairs.qsize()


class ServerConnection(BaseConnection):
    def __init__(self, key_pair: Tuple[bytes, bytes]) -> None:
        self.private_key, self.public_key = key_pair

    def handshake(self, client: socket.socket, client_address: Tuple[str, int]) -> None:
        len_header = int(client.recv(4).decode())
        self.request = OblivionRequest(client.recv(len_header).decode())  # 接收请求头
        self.request.remote_addr = client_address[0]
        self.request.remote_port = client_address[1]

        if self.request.method == "POST":
            client.sendall(length(self.public_key))  # 发送公钥长度
            client.sendall(self.public_key)  # 发送公钥
            len_encrypted_aes_key = int(client.recv(4).decode())  # 捕获AES_KEY长度
            encrypted_aes_key = client.recv(len_encrypted_aes_key)  # 捕获AES_KEY
            self.client_aes_key = decrypt_aes_key(
                encrypted_aes_key, self.private_key
            )  # 使用RSA私钥解密AES密钥
            self.request.POST = (
                OED(AES_KEY=self.client_aes_key).from_stream(client, 5).DATA
            )
        elif self.request.method == "GET":
            pass
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

    def prepare(self, tcp: socket.socket) -> None:
        len_client_public_key = int(tcp.recv(4).decode())  # 从客户端获得公钥长度
        client_public_key = tcp.recv(len_client_public_key)  # 从客户端获得公钥
        self.aes_key = generate_aes_key()  # 生成随机的AES密钥
        self.encrypted_aes_key = encrypt_aes_key(
            self.aes_key, client_public_key
        )  # 使用客户端RSA公钥加密AES密钥

        tcp.sendall(length(self.encrypted_aes_key))  # 发送AES_KEY长度
        tcp.sendall(self.encrypted_aes_key)  # 发送AES_KEY

    def response(self, tcp: socket.socket, request: OblivionRequest) -> None:
        if callable(self.res):
            plaintext = self.res(request)
        else:
            plaintext = self.res

        oed = OED(AES_KEY=self.aes_key).from_json_or_string(plaintext)
        oed.to_stream(tcp, 5)


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
        self.keypool = RSAKeyPairPool()

    def handle(
        self, client_tcp: socket.socket, client_address: Tuple[str, int]
    ) -> None:
        connection = ServerConnection(self.keypool.get())
        request = connection.solve(client_tcp, client_address)

        for hook in self.hooks:
            logger.debug(f"Checking Hook: {hook.olps}")
            if hook.is_valid_header(request):
                hook.prepare(client_tcp)
                hook.response(client_tcp, request)
                print(
                    f"Oblivion/1.0 {request.method} From {client_address[0]} {hook.olps} 200"
                )
                break

        if hook.is_valid_header(request):
            return

        self.not_found.prepare(client_tcp)
        self.not_found.response(client_tcp)
        client_tcp.close()
        print(f"Oblivion/1.0 From {client_address} {hook.olps} 404")

    def _run(self) -> NoReturn:
        print("Performing system checks...\n")
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.bind((self.host, self.port))
        tcp.listen(self.max_connections)
        keep_thread = Thread(target=lambda: self.keypool.keep_forever(10))
        keep_thread.daemon = True
        keep_thread.start()
        print(f"Starting server at Oblivion://{self.host}:{self.port}/")
        print("Quit the server by close the window.")

        while True:
            client, client_address = tcp.accept()  # 等待客户端连接
            client.settimeout(20)
            self.threadpool.submit(self.handle, client, client_address)

    def run(self) -> NoReturn:
        try:
            self._run()
        except KeyboardInterrupt:
            print("\nOblivion server closed.")
