from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA


def decrypt_aes_key(encrypted_aes_key, private_key):
    """ 使用RSA私钥解密AES密钥 """
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    aes_key = cipher.decrypt(encrypted_aes_key)
    return aes_key


def decrypt_message(ciphertext, tag, aes_key, nonce):
    """ 使用AES解密消息 """
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode()