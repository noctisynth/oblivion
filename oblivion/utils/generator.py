from Crypto import Random
from Crypto.PublicKey import RSA


def generate_key_pair():
    """ 生成RSA密钥对(私钥, 公钥) """
    key = RSA.generate(2048, Random.new().read)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key