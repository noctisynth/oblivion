from pathlib import Path


class File:
    def __init__(self, path) -> None:
        self.path = path

    def __bytes__(self) -> bytes:
        return (
            Path(self.path).resolve().read_bytes() if Path(self.path).exists() else b""
        )
