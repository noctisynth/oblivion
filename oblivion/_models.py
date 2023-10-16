import abc


class Connection:
    def __init__(self, host="localhost", port=813) -> None:
        self.host = host
        self.port = port

    @abc.abstractmethod
    def prepare():
        raise NotImplementedError

    @abc.abstractmethod
    def response(self):
        raise NotImplementedError

    @abc.abstractmethod
    def listen(self):
        raise NotImplementedError

    @abc.abstractmethod
    def handshake(self):
        raise NotImplementedError

    @abc.abstractmethod
    def recv(self):
        raise NotImplementedError

    @abc.abstractmethod
    def solve(self):
        raise NotImplementedError