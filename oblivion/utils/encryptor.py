from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

import Crypto.Hash.SHA256

def encrypt_message(message: str, aes_key: bytes):
    """ 使用AES加密消息 """
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return ciphertext, tag, cipher.nonce


def encrypt_aes_key(aes_key, public_key):
    """ 使用RSA公钥加密AES密钥 """
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=Crypto.Hash.SHA256)
    encrypted_aes_key = cipher.encrypt(aes_key)
    return encrypted_aes_key