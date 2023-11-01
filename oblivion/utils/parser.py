from ..exceptions import BadProtocol, InvalidOblivion

import re


def length(string):
    str_num = str(len(string))
    if len(str_num) == 4:
        return str_num.encode()

    list_num = list(str_num)
    while len(list_num) != 4:
        list_num.insert(0, "0")

    return "".join(list_num).encode()


class OblivionPath:
    def __init__(self, obl_str) -> None:
        pattern = r"^(?P<protocol>oblivion)?(?:://)?(?P<host>[^:/]+)(:(?P<port>\d+))?(?P<url>/.+)?$"
        match = re.match(pattern, obl_str)

        if match:
            self.protocol = match.group("protocol") or "oblivion"
            if self.protocol != "oblivion":
                raise BadProtocol("使用了未被支持的协定")

            self.host = match.group("host")
            self.port = match.group("port") or "80"
            self.port = int(self.port)
            self.olps = match.group("url") or "/"
        else:
            raise InvalidOblivion(f"地址`{obl_str}`不合法.")


class Oblivion:
    method: str
    olps: str
    version: str

    def __init__(self, **kwargs) -> None:
        self.version = "1.1"
        self.method = "GET"

        for var, value in kwargs.items():
            if value:
                self.__setattr__(var, value)

    def __repr__(self):
        return f"<Oblivion [{self.method}]>"

    @property
    def plain_text(self):
        return f"{self.method.upper()} {self.olps} Oblivion/{self.version}"


class OblivionRequest:
    method: str
    olps: str
    protocol: str
    version: str
    data: str
    plain_text: str
    POST: dict
    remote_addr: dict
    remote_port: int

    def __init__(self, header: str = None) -> None:
        self.plain_text = header
        match = re.match(r"(\w+) (\S+) (\w+)/(\d+\.\d+)", header)
        if match:
            self.method = match.group(1)
            self.olps = match.group(2)
            self.protocol = match.group(3)
            self.version = match.group(4)
        else:
            raise BadProtocol

    def __repr__(self) -> str:
        return self.plain_text