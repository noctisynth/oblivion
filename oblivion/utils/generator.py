from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import scrypt


def generate_key_pair():
    """生成ECDH密钥对(私钥, 公钥)"""
    key = ECC.generate(curve="P-256")
    return key.export_key(format="DER"), key.public_key().export_key(format="DER")


def generate_shared_key(__private_key, __public_key):
    """生成ECDH共享密钥"""
    return scrypt(
        (
            ECC.import_key(__public_key).pointQ * ECC.import_key(__private_key).d
        ).x.to_bytes(32, "big"),
        b"",
        16,
        N=2**12,
        r=8,
        p=1,
    )
