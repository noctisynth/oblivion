from typing import Callable
from ..utils.parser import Oblivion, OblivionPath, OblivionRequest

import abc
import asyncio


class BaseConnection:
    @abc.abstractmethod
    def prepare(self):
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
    method: str
    olps: str
    data: bytes | bytearray

    def __init__(
        self,
        method: str = None,
        olps: str = None,
        data: dict = None,
    ) -> None:
        self.method = method.upper()
        self.path = OblivionPath(olps)
        self.olps = self.path.olps
        self.oblivion = Oblivion(method=method, olps=self.olps)
        self.plain_text = self.oblivion.plain_text
        self.data = data
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


class BaseHook:
    def __init__(
        self, olps: str, res: str = "", handle: Callable = None, method="GET"
    ) -> None:
        self.olps = olps
        if res and handle:
            raise ValueError("不允许同时进行动态和静态处理.")

        if res:
            self.res = res
        else:
            self.res = handle

        self.method = method.upper()

    def __repr__(self) -> str:
        return f'<Hook "{self.olps}">'

    def __eq__(self, __value: object) -> bool:
        return self.is_valid(__value)

    def is_valid(self, olps: str) -> bool:
        return self.olps.rstrip("/") == olps.rstrip("/")

    def is_valid_header(self, header: OblivionRequest) -> bool:
        return header.olps == self.olps.rstrip("/")


class OblivionPackage:
    """Oblivion Package Basic Class"""

    length: bytes

    def __init__(self, **kwargs) -> None:
        for key, value in kwargs.items():
            self.__setattr__(key, value)

    def __repr__(self) -> str:
        return f"<{self.__name__} {self.plain_data[:8]}>"

    @property
    @abc.abstractmethod
    def plain_data(self) -> bytes:
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
        self.writer.close()
        await self.writer.wait_closed()
