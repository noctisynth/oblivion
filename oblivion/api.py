from .sessions import Session


def request(method="get", olps=None, data=None, key_pair=None):
    return Session().request(method, olps=olps, data=data, key_pair=key_pair)


def get(olps, key_pair=None):
    return request("get", olps, None, key_pair)


def post(olps, data=None, key_pair=None):
    return request("post", olps, data, key_pair)


def forward(olps):
    return request("forward", olps)
