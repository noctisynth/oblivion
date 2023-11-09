from multilogging import multilogger
from .models.client import Response, Request


logger = multilogger(name="Oblivion", payload="sessions")
""" `sessions`日志 """


class Session:
    def __repr__(self) -> str:
        return "<Session [Oblivion]>"

    def request(
        self,
        method: str,
        olps: str,
        data: dict = None,
        key_pair: tuple = None,
        verify: bool = True,
        tfo: bool = True,
    ) -> Response:
        req = Request(
            method=method,
            olps=olps,
            data=data,
            key_pair=key_pair,
            verify=verify,
            tfo=tfo,
        )
        req.prepare()
        return self.send(request=req)

    def send(self, request: Request = None) -> Response:
        if not request.prepared:
            request.prepare()

        # 发送请求
        request.send()
        return request.recv()

    def get(self, olps) -> Response:
        return self.request("GET", olps)

    def post(self, olps) -> Response:
        return self.request("POST", olps)

    def put(self, olps) -> Response:
        return self.request("PUT", olps)
