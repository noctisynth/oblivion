from multilogging import multilogger
from typing import Tuple, NoReturn

from ._models import BaseConnection, Stream

from ..utils.parser import Oblivion, length
from ..utils.encryptor import encrypt_aes_key, encrypt_message
from ..utils.decryptor import decrypt_aes_key, decrypt_message
from ..utils.generator import generate_key_pair, generate_aes_key

import socket
import asyncio


logger = multilogger(name="Oblivion", payload="models")
""" `models`日志 """


class ServerConnection(BaseConnection):
    def __init__(self, tcp: socket.socket) -> None:
        super().__init__()
        self.tcp = tcp
        self.client = None

    def prepare(self) -> None:
        pass

    def listen(self) -> Tuple[socket.socket, Tuple[str, int]]:
        self.private_key, self.public_key = generate_key_pair()
        self.client, self.client_address = self.tcp.accept()  # 等待客户端连接
        return self.client, self.client_address

    def handshake(self) -> bytes:
        self.client.sendall(length(self.public_key))  # 发送公钥长度
        self.client.sendall(self.public_key)  # 发送公钥
        len_encrypted_aes_key = int(self.client.recv(4).decode())  # 捕获AES_KEY长度
        encrypted_aes_key = self.client.recv(len_encrypted_aes_key)  # 捕获AES_KEY
        self.client_aes_key = decrypt_aes_key(
            encrypted_aes_key, self.private_key
        )  # 使用RSA私钥解密AES密钥
        return self.client_aes_key

    def recv(self) -> Tuple[bytes, bytes, bytes]:
        len_ciphertext = int(self.client.recv(4).decode())  # 捕获加密文本长度
        self.request_data = self.client.recv(len_ciphertext)  # 捕获加密文本
        len_nonce = int(self.client.recv(4).decode())  # 捕获nonce长度
        self.nonce = self.client.recv(len_nonce)  # 捕获nonce
        logger.debug(f"捕获到nonce: {self.nonce}")
        len_tag = int(self.client.recv(4).decode())  # 捕获tag长度
        self.tag = self.client.recv(len_tag)  # 捕获tag
        logger.debug(f"捕获到tag: {self.tag}")
        return self.request_data, self.tag, self.nonce

    def response(self) -> None:
        pass

    def solve(self) -> str:
        if not self.client:
            raise NotImplementedError

        self.handshake()
        self.recv()
        return decrypt_message(
            self.request_data, self.tag, self.client_aes_key, self.nonce
        )  # 使用AES解密消息

    @property
    def decrypted_message(self):
        return decrypt_message(
            self.request_data, self.tag, self.client_aes_key, self.nonce
        )


class Hook:
    def __init__(self, olps: str, data: str = "", method="GET") -> None:
        self.olps = olps
        self.data = data
        self.method = method.upper()

    def __eq__(self, __value: object) -> bool:
        return self.is_valid(__value)

    def is_valid(self, header: str) -> bool:
        olps = header.split(" ")[1]
        return self.olps.rstrip("/") == olps.rstrip("/")

    def prepare(self, tcp: socket.socket) -> None:
        len_client_public_key = int(tcp.recv(4).decode())  # 从客户端获得公钥长度
        client_public_key = tcp.recv(len_client_public_key)  # 从客户端获得公钥
        logger.debug(f"捕获到客户端公钥: {client_public_key.decode()}")

        self.aes_key = generate_aes_key()  # 生成随机的AES密钥
        self.encrypted_aes_key = encrypt_aes_key(
            self.aes_key, client_public_key
        )  # 使用客户端RSA公钥加密AES密钥

        tcp.sendall(length(self.encrypted_aes_key))  # 发送AES_KEY长度
        tcp.sendall(self.encrypted_aes_key)  # 发送AES_KEY

    def response(self, tcp: socket.socket) -> None:
        response, tag, nonce = encrypt_message(self.data, self.aes_key)  # 使用AES加密应答

        # 发送完整应答
        tcp.sendall(length(response))
        tcp.sendall(response)

        # 发送nonce
        tcp.sendall(length(nonce))
        tcp.sendall(nonce)

        # 发送tag
        tcp.sendall(length(tag))
        tcp.sendall(tag)

        tcp.close()


class AsyncHook:
    def __init__(self, olps: str, data: str = "", method="GET") -> None:
        self.olps = olps
        self.data = data
        self.method = method.upper()

    def __eq__(self, __value: object) -> bool:
        return self.is_valid(__value)

    def is_valid(self, header: str) -> bool:
        olps = header.split(" ")[1]
        return self.olps.rstrip("/") == olps.rstrip("/")

    async def prepare(self, tcp: Stream) -> None:
        len_client_public_key = int((await tcp.recv(4)).decode())  # 从客户端获得公钥长度
        client_public_key = await tcp.recv(len_client_public_key)  # 从客户端获得公钥
        logger.debug(f"捕获到客户端公钥: {client_public_key.decode()}")

        self.aes_key = generate_aes_key()  # 生成随机的AES密钥
        self.encrypted_aes_key = encrypt_aes_key(
            self.aes_key, client_public_key
        )  # 使用客户端RSA公钥加密AES密钥

        await tcp.sendall(length(self.encrypted_aes_key))  # 发送AES_KEY长度
        await tcp.sendall(self.encrypted_aes_key)  # 发送AES_KEY

    async def response(self, tcp: Stream) -> None:
        response, tag, nonce = encrypt_message(self.data, self.aes_key)  # 使用AES加密应答

        # 发送完整应答
        await tcp.sendall(length(response))
        await tcp.sendall(response)

        # 发送nonce
        await tcp.sendall(length(nonce))
        await tcp.sendall(nonce)

        # 发送tag
        await tcp.sendall(length(tag))
        await tcp.sendall(tag)

        await tcp.close()


class Hooks(list[Hook | AsyncHook]):
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

    def add(self, olps: str, data: str) -> bool:
        for hook in self:
            if hook.is_valid(olps):
                return False

        self.append(Hook(olps=olps, data=data, method="GET"))
        return True

    def edit(self, olps: str, data: str) -> bool:
        for index, hook in enumerate(self):
            if hook.is_valid(olps):
                self.insert(index, data)
                return True

        return False


class Server:
    def __init__(
        self,
        host="0.0.0.0",
        port=80,
        max_connection=5,
        hooks=[],
        not_found="404 Not Found",
    ) -> None:
        self.host = host
        self.port = port
        self.max_connections = max_connection
        self.hooks: Hooks = hooks
        self.not_found = Hook("/404", data=not_found)

    def prepare(self) -> socket.socket:
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.bind((self.host, self.port))
        self.tcp.listen(self.max_connections)
        return self.tcp

    def run(self) -> NoReturn:
        connection = ServerConnection(self.prepare())
        connection.prepare()

        while True:
            client_tcp, client_address = connection.listen()
            header = connection.solve()

            for hook in self.hooks:
                logger.debug(f"Checking Hook: {hook.olps}")
                if hook == header:
                    hook.prepare(client_tcp)
                    hook.response(client_tcp)

                    print(f"Oblivion/1.0 From {client_address} {hook.olps} 200")
                    break

            if hook == header:
                continue

            self.not_found.prepare(client_tcp)
            self.not_found.response(client_tcp)
            print(f"Oblivion/1.0 From {client_address} {hook.olps} 404")


class AsyncServerConnection(BaseConnection):
    tcp: Stream

    def __init__(self) -> None:
        super().__init__()

    async def prepare(self) -> None:
        self.private_key, self.public_key = generate_key_pair()

    async def handshake(self) -> bytes:
        await self.tcp.sendall(length(self.public_key))  # 发送公钥长度
        await self.tcp.sendall(self.public_key)  # 发送公钥
        len_encrypted_aes_key = int((await self.tcp.recv(4)).decode())  # 捕获AES_KEY长度
        encrypted_aes_key = await self.tcp.recv(len_encrypted_aes_key)  # 捕获AES_KEY
        self.client_aes_key = decrypt_aes_key(
            encrypted_aes_key, self.private_key
        )  # 使用RSA私钥解密AES密钥
        return self.client_aes_key

    async def recv(self) -> Tuple[bytes, bytes, bytes]:
        len_ciphertext = int((await self.tcp.recv(4)).decode())  # 捕获加密文本长度
        self.request_data = await self.tcp.recv(len_ciphertext)  # 捕获加密文本
        len_nonce = int((await self.tcp.recv(4)).decode())  # 捕获nonce长度
        self.nonce = await self.tcp.recv(len_nonce)  # 捕获nonce
        logger.debug(f"捕获到nonce: {self.nonce}")
        len_tag = int((await self.tcp.recv(4)).decode())  # 捕获tag长度
        self.tag = await self.tcp.recv(len_tag)  # 捕获tag
        logger.debug(f"捕获到tag: {self.tag}")
        return self.request_data, self.tag, self.nonce

    async def response(self) -> None:
        pass

    async def solve(self) -> str:
        if not self.tcp:
            raise NotImplementedError

        await self.handshake()
        await self.recv()
        return decrypt_message(
            self.request_data, self.tag, self.client_aes_key, self.nonce
        )  # 使用AES解密消息

    @property
    def decrypted_message(self):
        return decrypt_message(
            self.request_data, self.tag, self.client_aes_key, self.nonce
        )


class AsyncServer:
    def __init__(
        self,
        host="0.0.0.0",
        port=80,
        max_connection=5,
        hooks=[],
        not_found="404 Not Found",
    ) -> None:
        self.host = host
        self.port = port
        self.max_connections = max_connection
        self.hooks: Hooks = hooks
        self.not_found = Hook("/404", data=not_found)

    async def prepare(self) -> socket.socket:
        self.tcp = await asyncio.start_server(self.handle, self.host, self.port)
        self.connection = AsyncServerConnection()
        return self.tcp

    async def handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> bool:
        stream = Stream(reader, writer)
        self.connection.tcp = stream
        await self.connection.prepare()
        header = await self.connection.solve()

        for hook in self.hooks:
            logger.debug(f"Checking Hook: {hook.olps}")
            if hook == header:
                await hook.prepare(stream)
                await hook.response(stream)

                print(
                    f"Oblivion/1.0 From {writer.get_extra_info('peername')[0]} {hook.olps} 200"
                )
                return

        if hook == header:
            return

        await self.not_found.prepare(stream)
        await self.not_found.response(stream)
        print(f"Oblivion/1.0 From {writer[0]} {hook.olps} 404")

    async def _run(self) -> NoReturn:
        await self.prepare()

        async with self.tcp:
            await self.tcp.serve_forever()

    def run(self):
        asyncio.run(self._run())


if __name__ == "__main__":
    print(Oblivion(method="get", olps="/test").plain_text)
