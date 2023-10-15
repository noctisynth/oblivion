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

        self.server_public_key = self.tcp.recv(1024)
        logger.debug(f"接收到的公钥: {self.server_public_key.decode()}")

        self.aes_key = Random.get_random_bytes(16) # 生成随机的AES密钥
        self.encrypted_aes_key = encrypt_aes_key(self.aes_key, self.server_public_key) # 使用RSA公钥加密AES密钥
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

        private_key, public_key = generate_key_pair()
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

        self.data = decrypt_message(encrypted_data, None, decrypted_aes_key, nonce) # 使用AES解密应答

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
            response = client_socket.recv(len_ciphertext) # 捕获加密文本
            len_nonce = int(client_socket.recv(4).decode()) # 捕获nonce长度
            nonce = client_socket.recv(len_nonce) # 捕获nonce

            header = decrypt_message(response, None, decrypted_aes_key, nonce) # 使用AES解密消息

            logger.debug(f"Header: {header}")
            for hook in self.hooks:
                logger.debug(f"Check Hook: {hook.olps}")
                if hook == header:
                    client_public_key = client_socket.recv(1024) # 从客户端获得公钥
                    logger.debug(f"捕获到客户端公钥: {client_public_key.decode()}")

                    self.aes_key = Random.get_random_bytes(16) # 生成随机的AES密钥
                    self.encrypted_aes_key = encrypt_aes_key(self.aes_key, client_public_key) # 使用客户端RSA公钥加密AES密钥

                    client_socket.sendall(length(self.encrypted_aes_key)) # 发送AES_KEY长度
                    client_socket.sendall(self.encrypted_aes_key) # 发送AES_KEY

                    response, _, nonce = encrypt_message(hook.data, self.aes_key) # 使用AES加密应答

                    # 发送完整应答
                    client_socket.sendall(length(response))
                    client_socket.sendall(response)

                    # 发送nonce
                    client_socket.sendall(length(nonce))
                    client_socket.sendall(nonce)

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