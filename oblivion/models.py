from multilogging import multilogger
from typing import List, Tuple, NoReturn
from Crypto import Random

from ._models import Connection

from .utils.parser import OblivionPath, Oblivion, length
from .utils.encryptor import encrypt_aes_key, encrypt_message
from .utils.decryptor import decrypt_aes_key, decrypt_message
from .utils.generator import generate_key_pair

from . import exceptions

import socket


logger = multilogger(name="Oblivion", payload="models")
""" `models`日志 """


class ServerConnection(Connection):
    def __init__(self, tcp: socket.socket) -> None:
        super().__init__()
        self.tcp = tcp
        self.client = None

    def prepare(self):
        pass

    def listen(self):
        self.private_key, self.public_key = generate_key_pair()
        self.client, self.client_address = self.tcp.accept() # 等待客户端连接
        return self.client, self.client_address

    def handshake(self) -> bytes:
        self.client.sendall(length(self.public_key)) # 发送公钥长度
        self.client.sendall(self.public_key) # 发送公钥
        len_encrypted_aes_key = int(self.client.recv(4).decode()) # 捕获AES_KEY长度
        encrypted_aes_key = self.client.recv(len_encrypted_aes_key) # 捕获AES_KEY
        self.client_aes_key = decrypt_aes_key(encrypted_aes_key, self.private_key) # 使用RSA私钥解密AES密钥
        return self.client_aes_key

    def recv(self) -> Tuple[bytes, bytes]:
        len_ciphertext = int(self.client.recv(4).decode()) # 捕获加密文本长度
        self.request_data = self.client.recv(len_ciphertext) # 捕获加密文本
        len_nonce = int(self.client.recv(4).decode()) # 捕获nonce长度
        self.nonce = self.client.recv(len_nonce) # 捕获nonce
        logger.debug(f"捕获到nonce: {self.nonce}")
        len_tag = int(self.client.recv(4).decode()) # 捕获tag长度
        self.tag = self.client.recv(len_tag) # 捕获tag
        logger.debug(f"捕获到tag: {self.tag}")
        return self.request_data, self.tag, self.nonce

    def response(self):
        pass

    def solve(self) -> str:
        if not self.client:
            raise NotImplementedError

        self.handshake()
        self.recv()
        return decrypt_message(self.request_data, self.tag, self.client_aes_key, self.nonce) # 使用AES解密消息


class Request:
    def __init__(
        self,
        method=None,
        olps=None,
    ) -> None:
        self.method = method
        self.path = OblivionPath(olps)
        self.olps = self.path.olps
        self.oblivion = Oblivion(
            method=method,
            olps=self.olps
        )
        self.plain_text = self.oblivion.plain_text
        self.prepared = False

    def __repr__(self) -> str:
        return f"<Request [{self.method}] {self.olps}>"

    def prepare(self):
        logger.debug(f"尝试链接 {self.path.host}...")
        try:
            self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp.connect((self.path.host, self.path.port))
        except ConnectionRefusedError:
            raise exceptions.ConnectionRefusedError("向服务端的链接请求被拒绝, 可能是服务端由于宕机.")

        len_server_public_key = int(self.tcp.recv(4).decode())
        server_public_key = self.tcp.recv(len_server_public_key)
        logger.debug(f"接收到的公钥: {server_public_key.decode()}")

        self.aes_key = Random.get_random_bytes(16) # 生成随机的AES密钥
        encrypted_aes_key = encrypt_aes_key(self.aes_key, server_public_key) # 使用RSA公钥加密AES密钥
        self.tcp.sendall(length(encrypted_aes_key)) # 发送AES_KEY长度
        self.tcp.sendall(encrypted_aes_key) # 发送AES_KEY

        self.prepared = True

    def send(self):
        if not self.prepared:
            self.prepare()

        ciphertext, tag, nonce = encrypt_message(self.plain_text, self.aes_key) # 使用AES加密请求头

        # 发送完整请求
        logger.debug(f"请求地址: {self.olps}")
        self.tcp.sendall(length(ciphertext))
        self.tcp.sendall(ciphertext)

        # 发送nonce
        logger.debug(f"发送nonce: {nonce}")
        self.tcp.sendall(length(nonce))
        self.tcp.sendall(nonce)

        # 发送tag
        logger.debug(f"发送tag: {tag}")
        self.tcp.sendall(length(tag))
        self.tcp.sendall(tag)

    def recv(self):
        if not self.prepared:
            raise NotImplementedError

        private_key, public_key = generate_key_pair()
        self.tcp.sendall(length(public_key)) # 发送本地公钥长度
        self.tcp.sendall(public_key) # 发送本地公钥

        len_encrypted_aes_key = int(self.tcp.recv(4).decode()) # 捕获AES_KEY长度
        encrypted_aes_key = self.tcp.recv(len_encrypted_aes_key) # 捕获AES_KEY
        decrypted_aes_key = decrypt_aes_key(encrypted_aes_key, private_key) # 使用RSA私钥解密AES密钥
        logger.debug("捕获到服务端传回的AES_KEY.")

        # 接受请求返回
        len_recv = int(self.tcp.recv(4).decode())
        encrypted_data = self.tcp.recv(len_recv)
        len_nonce = int(self.tcp.recv(4).decode()) # 捕获nonce长度
        nonce = self.tcp.recv(len_nonce) # 捕获nonce

        len_tag = int(self.tcp.recv(4).decode()) # 捕获tag长度
        tag = self.tcp.recv(len_tag) # 捕获tag

        self.data = decrypt_message(encrypted_data, tag, decrypted_aes_key, nonce) # 使用AES解密应答

        return self.data


class Hook:
    def __init__(self, olps: str, data: str="", method="GET") -> None:
        self.olps = olps
        self.data = data
        self.method = method.upper()

    def __eq__(self, __value: object) -> bool:
        return self.is_valid(__value)

    def is_valid(self, header: str):
        olps = header.split(" ")[1]
        return self.olps.rstrip("/") == olps.rstrip("/")

    def prepare(self, tcp: socket.socket):
        len_client_public_key = int(tcp.recv(4).decode()) # 从客户端获得公钥长度
        client_public_key = tcp.recv(len_client_public_key) # 从客户端获得公钥
        logger.debug(f"捕获到客户端公钥: {client_public_key.decode()}")

        self.aes_key = Random.get_random_bytes(16) # 生成随机的AES密钥
        self.encrypted_aes_key = encrypt_aes_key(self.aes_key, client_public_key) # 使用客户端RSA公钥加密AES密钥

        tcp.sendall(length(self.encrypted_aes_key)) # 发送AES_KEY长度
        tcp.sendall(self.encrypted_aes_key) # 发送AES_KEY

    def response(self, tcp: socket.socket):
        response, tag, nonce = encrypt_message(self.data, self.aes_key) # 使用AES加密应答

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


class Server:
    def __init__(
        self,
        host="0.0.0.0",
        port=80,
        max_connection=5,
        hooks=[],
        not_found="404 Not Found"
    ) -> None:
        self.host = host
        self.port = port
        self.max_connections = max_connection
        self.hooks: List[Hook] = hooks
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


if __name__ == "__main__":
    print(Oblivion(
        method="get",
        olps="/test"
    ).plain_text)