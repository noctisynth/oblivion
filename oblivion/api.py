from .sessions import Session


def request(method="get", olps=None):
    return Session().request(method, olps=olps)


def get(olps):
    return request("get", olps)


def post(olps):
    return request("post", olps)


def forward(olps):
    return request("forward", olps)