from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

import Crypto.Hash.SHA256


def decrypt_aes_key(encrypted_aes_key, private_key):
    """使用RSA私钥解密AES密钥"""
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=Crypto.Hash.SHA256)
    aes_key = cipher.decrypt(encrypted_aes_key)
    return aes_key


def decrypt_message(ciphertext, tag, aes_key, nonce, verify=True):
    """使用AES解密消息"""
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = (
        cipher.decrypt_and_verify(ciphertext, tag)
        if verify
        else cipher.decrypt(ciphertext)
    )
    return plaintext.decode()
