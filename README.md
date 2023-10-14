# Oblivion

私有端对端加密通讯协议

## Features
1. 实现动态修改`Hooks`
2. 实现身份验证
3. 实现`2FA`验证

## 构建一个基本的`Oblivion`服务端
```python
from oblivion.models import Server, Hook


hooks = [
    Hook("/test", "请快点毁灭人类!")
]

if __name__ == "__main__":
    Server(port=813, hooks=hooks).run()
```
其中, `Hook`类声明地址及改地址的信息.

## 对`Oblivion`服务器进行访问请求
```python
import oblivion


print(oblivion.get("oblivion://127.0.0.1:813/test"))
```
它将输出`请快点毁灭人类!`.