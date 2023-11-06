# Oblivion

私有端对端加密通讯协议, 使用ECDH加密通讯.

## 构建一个基本的`Oblivion`服务端

```python
from oblivion.models import Server, Hook

hooks = [Hook("/test", "请快点毁灭人类!")]


@hooks.regist("/test2")
def test2(request):
    return "人类必须快点毁灭!"


if __name__ == "__main__":
    Server(port=813, hooks=hooks).run()
```

其中, `Hook`类声明地址及改地址的信息.

## 对`Oblivion`服务器进行访问请求

```python
import oblivion


print(oblivion.get("oblivion://127.0.0.1:813/test2"))
```

它将输出`人类必须快点毁灭!`.
