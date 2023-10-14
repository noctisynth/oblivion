from multilogging import multilogger
from typing import List
from Crypto import Random

from oblivion.utils.parser import Oblivion

from .utils.parser import OblivionPath
from .utils.encryptor import encrypt_aes_key, encrypt_message
from .utils.decryptor import decrypt_aes_key, decrypt_message
from .utils.generator import generate_key_pair
from .utils.parser import length

from . import exceptions

import socket


logger = multilogger(name="Oblivion", payload="models")
""" `models`日志 """


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

        self.public_key = self.tcp.recv(1024)
        logger.debug(f"接收到的公钥: {self.public_key.decode()}")

        self.aes_key = Random.get_random_bytes(16) # 生成随机的AES密钥
        self.encrypted_aes_key = encrypt_aes_key(self.aes_key, self.public_key) # 使用RSA公钥加密AES密钥
        self.tcp.sendall(length(self.encrypted_aes_key)) # 发送AES_KEY长度
        self.tcp.sendall(self.encrypted_aes_key) # 发送AES_KEY

        self.prepared = True

    def send(self):
        if not self.prepared:
            self.prepare()

        ciphertext, _, nonce = encrypt_message(self.plain_text, self.aes_key) # 使用AES加密请求头

        # 发送完整请求
        logger.debug(f"请求地址: {self.olps}")
        self.tcp.sendall(length(ciphertext))
        self.tcp.sendall(ciphertext)

        # 发送nonce
        self.tcp.sendall(length(nonce))
        self.tcp.sendall(nonce)

    def recv(self):
        if not self.prepared:
            raise NotImplementedError

        # 接受请求返回
        len_recv = int(self.tcp.recv(4).decode())
        self.data = self.tcp.recv(len_recv)
        return self.data


class Hook:
    def __init__(self, olps: str, data: str="", method="GET") -> None:
        self.olps = olps
        self.data = data.encode()
        self.method = method.upper()
        self.length = length(self.data)

    def __eq__(self, __value: object) -> bool:
        return self.is_valid(__value)

    def is_valid(self, header: str):
        olps = header.split(" ")[1]
        return self.olps.rstrip("/") == olps.rstrip("/")


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
        self.not_found = not_found

    def run(self):
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.bind((self.host, self.port))
        self.tcp.listen(self.max_connections)

        # --------------------
        while True:
            private_key, public_key = generate_key_pair()

            client_socket, client_address = self.tcp.accept() # 等待客户端连接
            client_socket.sendall(public_key) # 发送公钥

            len_encrypted_aes_key = int(client_socket.recv(4).decode()) # 捕获AES_KEY长度
            encrypted_aes_key = client_socket.recv(len_encrypted_aes_key) # 捕获AES_KEY

            decrypted_aes_key = decrypt_aes_key(encrypted_aes_key, private_key) # 使用RSA私钥解密AES密钥
            len_ciphertext = int(client_socket.recv(4).decode()) # 捕获加密文本长度
            ciphertext = client_socket.recv(len_ciphertext) # 捕获加密文本
            len_nonce = int(client_socket.recv(4).decode()) # 捕获nonce长度
            nonce = client_socket.recv(len_nonce) # 捕获nonce

            header = decrypt_message(ciphertext, None, decrypted_aes_key, nonce) # 使用AES解密消息

            logger.debug(f"Header: {header}")
            for hook in self.hooks:
                logger.debug(f"Check Hook: {hook.olps}")
                if hook == header:
                    client_socket.sendall(hook.length)
                    client_socket.sendall(hook.data)
                    client_socket.close()
                    print(f"Oblivion/1.0 From {client_address} {hook.olps} 200")
                    break

            if hook == header:
                continue

            client_socket.sendall(length(self.not_found.encode()))
            client_socket.sendall(self.not_found.encode())
            print(f"Oblivion/1.0 From {client_address} {hook.olps} 404")


if __name__ == "__main__":
    print(Oblivion(
        method="get",
        olps="/test"
    ).plain_text)