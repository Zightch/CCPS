# Key库
头文件[`jni/key.h`](jni/key.h)  
源文件[`jni/key.c`](jni/key.c)  
集成了如下功能

| 函数名 | 功能 |
| :-: | :-: |
| genKeyPair | 生成密钥对 |
| genSharedKey | 用自己私钥与对端公钥生成共享密钥 |
| encryptData | 用密钥与IV数组加密消息 |
| decryptData | 用密钥与IV数组解密消息 |
| verify | 用公钥验对消息验签 |

* 生成密钥对与计算公钥使用X25519算法
* 其中加密与解密算法使用AES-256-GCM
* verify验签使用ED25519算法
* 构建安卓平台时请确保OpenSSL库与Key库的Android api为22
