from typing import Callable
from ..utils.parser import OblivionRequest
from .router import Route

import abc


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


class BaseHook:
    def __init__(
        self,
        route: str | Route,
        res: str = "",
        handle: Callable = None,
        method: str = "GET",
    ) -> None:
        self.route = route
        if res and handle:
            raise ValueError("不允许同时进行动态和静态处理.")

        if res:
            self.res = res
        else:
            self.res = handle

        self.method = method.upper()

    def __repr__(self) -> str:
        return f'<Hook "{self.route}">'

    def __eq__(self, __value: object) -> bool:
        return self.is_valid(__value)

    def is_valid(self, olps: str) -> bool:
        return (
            self.route.verify(olps)
            if isinstance(self.route, Route)
            else olps.rstrip("/") == self.route.rstrip("/")
        )

    def is_valid_header(self, header: OblivionRequest) -> bool:
        return (
            self.route.verify(header.olps)
            if isinstance(self.route, Route)
            else header.olps.rstrip("/") == self.route.rstrip("/")
        )


class BasePackage:
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
