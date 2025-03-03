# Oblivion

> [!WARNING]
> 此项目已经不再维护，我们使用 Rust 重写了 Oblivion 的逻辑，并在截至此文档修订时的 v2.0 版本中对 Oblivion 协议的标准进行了破坏性变更。
> 我们不会对此项目中的任何漏洞或造成的任何未知后果负责，也不会再对可能的任何问题进行修复。
> 如果你对 Oblivion 协议有兴趣，请前往 [Oblivion Rust](https://github.com/noctisynth/oblivion-rs)。

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
