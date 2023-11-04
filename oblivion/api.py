from .sessions import Session


def request(method="get", olps=None, data=None, key_pair=None, verify=True):
    return Session().request(method, olps=olps, data=data, key_pair=key_pair, verify=verify)


def get(olps, key_pair=None, verify=True):
    return request("get", olps, None, key_pair, verify)


def post(olps, data=None, key_pair=None, verify=True):
    return request("post", olps, data, key_pair, verify)


def forward(olps):
    return request("forward", olps)
