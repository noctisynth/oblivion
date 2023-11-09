class Route:
    def __init__(self, olps: str) -> None:
        self.olps = olps

    def verify(self, __olps: str) -> bool:
        return __olps.rstrip("/") == __olps.rstrip("/")


class Startswith(Route):
    def __init__(self, __startswith: str | tuple) -> None:
        self.olps = __startswith

    def verify(self, __olps: str):
        return __olps.rstrip("/").startswith(self.olps)
