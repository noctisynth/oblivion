class RequestException(Exception):
    """ `Oblivion`异常基类 """


class BadProtocol(RequestException):
    """ 协议错误 """


class ConnectionRefusedError(RequestException, ConnectionRefusedError):
    """ 向服务端的链接请求被拒绝 """


class InvalidOblivion(RequestException, ValueError):
    """ Oblivion地址不合法 """