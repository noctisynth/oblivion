from .sessions import Session


def request(method="get", olps="/"):
    return Session().request(method, olps=olps)


def get(olps="/"):
    return request("get", olps)


def post(olps="/"):
    return request("post", olps)