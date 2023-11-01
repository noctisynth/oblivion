from .sessions import Session


def request(method="get", olps=None, data=None):
    return Session().request(method, olps=olps, data=data)


def get(olps):
    return request("get", olps)


def post(olps, data=None):
    return request("post", olps, data)


def forward(olps):
    return request("forward", olps)
