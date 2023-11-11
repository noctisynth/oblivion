from Crypto.Cipher import AES


def decrypt_bytes(
    cipherbytes: bytes, tag: bytes, aes_key: bytes, nonce: bytes, verify: bool = True
):
    """使用AES解密字节"""
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = (
        cipher.decrypt_and_verify(cipherbytes, tag)
        if verify
        else cipher.decrypt(cipherbytes)
    )
    return plaintext
