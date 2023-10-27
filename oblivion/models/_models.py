from ..utils.parser import Oblivion, OblivionPath

import abc
import asyncio


class BaseConnection:
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


class BaseRequest:
    def __init__(
        self,
        method=None,
        olps=None,
    ) -> None:
        self.method = method
        self.path = OblivionPath(olps)
        self.olps = self.path.olps
        self.oblivion = Oblivion(method=method, olps=self.olps)
        self.plain_text = self.oblivion.plain_text
        self.prepared = False

    @abc.abstractmethod
    def __repr__(self) -> str:
        return "<BaseRequest [Oblivion]>"

    @abc.abstractmethod
    def prepare(self) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def send(self) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def recv(self) -> str:
        raise NotImplementedError


class Stream:
    def __init__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.reader = reader
        self.writer = writer

    async def recv(self, __bufsize: int):
        return await self.reader.read(__bufsize)

    async def sendall(self, __data: bytes | bytearray):
        self.writer.write(__data)
        return await self.writer.drain()

    async def close(self):
        return self.writer.close()
