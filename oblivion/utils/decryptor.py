from Crypto.Cipher import AES


def decrypt_message(ciphertext, tag, aes_key, nonce, verify=True):
    """使用AES解密消息"""
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = (
        cipher.decrypt_and_verify(ciphertext, tag)
        if verify
        else cipher.decrypt(ciphertext)
    )
    return plaintext.decode()
