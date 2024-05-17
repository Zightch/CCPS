# Key库
集成了如下功能

| 函数名 | 功能 |
| :-: |:-:|
| genX25519KeyPair | 生成X25519密钥对  |
| genSharedKey | 用自己私钥与公钥生成共享密钥 |
| encryptData | 用密钥与IV数组加密消息 |
| decryptData | 用密钥与IV数组解密消息 |

其中加密与解密算法使用AES-256-GCM
