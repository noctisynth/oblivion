from Crypto.Cipher import AES
from Crypto import Random


def encrypt_message(message: str, aes_key: bytes):
    """使用AES加密消息"""
    nonce = Random.get_random_bytes(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return ciphertext, tag, cipher.nonce


def encrypt_data(data: bytes, aes_key: bytes):
    """使用AES加密字节"""
    nonce = Random.get_random_bytes(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, tag, cipher.nonce
