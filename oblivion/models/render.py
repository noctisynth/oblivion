from pathlib import Path

import abc
import json


class BaseResponse:
    status_code: int = 200

    @abc.abstractmethod
    def __bytes__(self) -> bytes:
        raise NotImplementedError


class FileResponse(BaseResponse):
    def __init__(self, path: str | Path, status_code: int = 200) -> None:
        self.path = Path(path).resolve()
        self.status_code = status_code

    def __bytes__(self) -> bytes:
        if self.path.exists():
            return self.path.read_bytes()
        else:
            self.status_code = 404
            return b""


class TextResponse(BaseResponse):
    def __init__(
        self, text: str, status_code: int = 200, encoding: str = "utf-8"
    ) -> None:
        self.text = str(text)
        self.status_code = status_code
        self.encoding = encoding

    def __bytes__(self) -> bytes:
        return self.text.encode(self.encoding)


class JsonResponse(BaseResponse):
    def __init__(
        self, data: str | list | dict, status_code: int = 200, encoding: str = "utf-8"
    ) -> None:
        if isinstance(data, (dict, list)):
            self.data = json.dumps(data)
        else:
            self.data = data
        self.status_code = status_code
        self.encoding = encoding

    def __bytes__(self) -> bytes:
        return self.data.encode(self.encoding)
