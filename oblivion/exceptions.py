class RequestException(Exception):
    """ `Oblivion`异常基类 """


class BadProtocol(RequestException):
    """ 协议错误 """


class ConnectionRefusedError(RequestException, ConnectionRefusedError):
    """ 向服务端的链接请求被拒绝 """


class InvalidOblivion(RequestException, ValueError):
    """ Oblivion地址不合法 """


class AdressAlreadyInUse(RequestException):
    """ 绑定地址被占用 """


class UnexceptedDisconnection(RequestException):
    """ 意外与远程端断开连接 """


class BadBytes(RequestException):
    """ 错误的连接协议 """


class ConnectTimedOut(RequestException):
    """ 响应超时 """