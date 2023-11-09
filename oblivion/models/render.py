from pathlib import Path

import abc
import json


class BaseResponse:
    @abc.abstractmethod
    def __bytes__(self) -> bytes:
        raise NotImplementedError


class FileResponse(BaseResponse):
    def __init__(self, path) -> None:
        self.path = path

    def __bytes__(self) -> bytes:
        return (
            Path(self.path).resolve().read_bytes() if Path(self.path).exists() else b""
        )


class TextResponse(BaseResponse):
    def __init__(self, text: str, encoding: str = "utf-8") -> None:
        self.text = text
        self.encoding = encoding

    def __bytes__(self) -> bytes:
        return self.text.encode(self.encoding)


class JsonResponse(BaseResponse):
    def __init__(self, data: str | dict, encoding: str = "utf-8") -> None:
        if isinstance(data, dict):
            self.data = json.dumps(data)
        else:
            self.data = data
        self.encoding = encoding

    def __bytes__(self) -> bytes:
        return self.data.encode(self.encoding)
