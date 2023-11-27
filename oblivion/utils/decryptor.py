from Crypto.Cipher import AES


def decrypt_bytes(
    cipherbytes: bytes, tag: bytes, aes_key: bytes, nonce: bytes, verify: bool = True
) -> bytes:
    """使用AES解密字节"""
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return (
        cipher.decrypt_and_verify(cipherbytes, tag)
        if verify
        else cipher.decrypt(cipherbytes)
    )
