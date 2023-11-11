from .sessions import Session


def request(
    method="get", olps=None, data=None, file=None, key_pair=None, verify=True, tfo=True
):
    return Session().request(
        method,
        olps=olps,
        data=data,
        file=file,
        key_pair=key_pair,
        verify=verify,
        tfo=tfo,
    )


def get(olps, key_pair=None, verify=True, tfo=True):
    return request("get", olps, None, None, key_pair, verify, tfo)


def post(olps, data=None, file=None, key_pair=None, verify=True, tfo=True):
    return request("post", olps, data, file, key_pair, verify, tfo)


def put(olps, data=None, file=None, key_pair=None, verify=True, tfo=True):
    return request("put", olps, data, file, key_pair, verify, tfo)


def forward(olps, data=None, file=None, key_pair=None, verify=True, tfo=True):
    return request("forward", olps, data, file, key_pair, verify, tfo)
