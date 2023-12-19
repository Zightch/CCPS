#include "Key.h"
#include <openssl/evp.h>
#include <QMutexLocker>
#include "Dump.h"

namespace Key {
    QMutex genX25519Key;
    QMutex getPubKey;
    QMutex checksum0;
    QMutex checksum1;
    QMutex checksums;
    QMutex genSharedKey;
    QMutex encryptData;
    QMutex decryptData;
}

void *genX25519Key() {
    QMutexLocker ml(&Key::genX25519Key);
    void *pkey = nullptr;
    EVP_PKEY_CTX *pctx;

    //为X25519算法创建上下文
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (pctx == nullptr) {
        // Handle error
        return nullptr;
    }

    // Initialize the context
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        // Handle error
        EVP_PKEY_CTX_free(pctx);
        return nullptr;
    }

    //生成密钥对
    if (EVP_PKEY_keygen(pctx, (EVP_PKEY **) &pkey) <= 0) {
        // Handle error
        EVP_PKEY_CTX_free(pctx);
        return nullptr;
    }

    // Free the context
    EVP_PKEY_CTX_free(pctx);

    // Return the key pair
    return pkey;
}

QByteArray getPubKey(void *key) {
    QMutexLocker ml(&Key::getPubKey);
    QByteArray tmp;
    unsigned char tmpC[32] = {0};
    size_t len;
    if (EVP_PKEY_get_raw_public_key((EVP_PKEY *) key, tmpC, &len) > 0)
        tmp.append((const char *) tmpC, 32);
    return tmp;
}

QByteArray genSharedKey(void *k, const QByteArray &d) {
    QMutexLocker ml(&Key::genSharedKey);

    // Create a peer key from raw public key data
    auto peerKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, (unsigned char *) d.data(), d.size());
    if (peerKey == nullptr)
        return "";

    // Create a context for the X25519 algorithm
    auto pctx = EVP_PKEY_CTX_new_from_pkey(nullptr, (EVP_PKEY *) k, nullptr);
    if (pctx == nullptr) {
        // Handle error
        EVP_PKEY_free(peerKey);
        return "";
    }

    // Initialize the context
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        // Handle error
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(peerKey);
        return "";
    }

    // Set the peer key
    if (EVP_PKEY_derive_set_peer(pctx, peerKey) <= 0) {
        // Handle error
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(peerKey);
        return "";
    }

    // Determine the shared key buffer length
    size_t size = 0;
    if (EVP_PKEY_derive(pctx, nullptr, &size) <= 0) {
        // Handle error
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(peerKey);
        return "";
    }

    // Allocate memory for the shared key
    auto shared = (unsigned char *) OPENSSL_malloc(size);
    if (shared == nullptr) {
        // Handle error
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(peerKey);
        return "";
    }

    // Derive the shared key
    if (EVP_PKEY_derive(pctx, shared, &size) <= 0) {
        // Handle error
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(peerKey);
        OPENSSL_free(shared);
        return "";
    }

    // Free the context and the peer key
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(peerKey);

    // Return the shared secret as a QByteArray
    QByteArray tmp;
    tmp.append((char *) shared, (qsizetype) size);
    OPENSSL_free(shared);
    return tmp;
}

// 使用给定密钥和IV使用AES-256-GCM加密消息
QByteArray encryptData(const QByteArray &key, unsigned char IV[16], const QByteArray &msg) {
    QMutexLocker ml(&Key::encryptData);
    EVP_CIPHER_CTX *ctx;
    unsigned char *cipher;
    int len;

    // 为AES-256-GCM密码创建上下文
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
        // Handle error
        return "";

    // Initialize the context
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0) {
        // Handle error
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    // Set the IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, nullptr) <= 0) {
        // Handle error
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    // Set the key and IV
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, (unsigned char *) key.data(), IV) <= 0) {
        // Handle error
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    // 为密文分配内存
    cipher = (unsigned char *) OPENSSL_malloc(msg.size() + 16); // 16 bytes for the tag
    if (cipher == nullptr) {
        // Handle error
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    // 加密消息
    if (EVP_EncryptUpdate(ctx, cipher, &len, (unsigned char *) msg.data(), (int) msg.size()) <= 0) {
        // Handle error
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_free(cipher);
        return "";
    }
    qsizetype cipherLen = len;

    // 完成加密
    if (EVP_EncryptFinal_ex(ctx, cipher + len, &len) <= 0) {
        // Handle error
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_free(cipher);
        return "";
    }
    cipherLen += len;

    // Get the tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, cipher + cipherLen) <= 0) {
        // Handle error
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_free(cipher);
        return "";
    }
    cipherLen += 16;

    // Free the context
    EVP_CIPHER_CTX_free(ctx);

    QByteArray tmp;
    tmp.append((char *) cipher, cipherLen);
    OPENSSL_free(cipher);
    // Return the ciphertext
    return tmp;
}

// 使用给定密钥和IV使用AES-256-GCM解密消息
QByteArray decryptData(const QByteArray &key, unsigned char IV[16], const QByteArray &cipher) {
    QMutexLocker ml(&Key::decryptData);
    EVP_CIPHER_CTX *ctx;
    unsigned char *msg;
    int len;

    // Create a context for the AES-256-GCM cipher
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
        return "";

    // Initialize the context
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0) {
        // Handle error
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    // Set the IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, nullptr) <= 0) {
        // Handle error
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    // Set the key and IV
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, (unsigned char *) key.data(), IV) <= 0) {
        // Handle error
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    // Allocate memory for the message
    msg = (unsigned char *) OPENSSL_malloc(cipher.size() - 16); // 16 bytes for the tag
    if (msg == nullptr) {
        // Handle error
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    // Decrypt the message
    if (EVP_DecryptUpdate(ctx, msg, &len, (unsigned char *) cipher.data(), (int) (cipher.size() - 16)) <= 0) {
        // Handle error
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_free(msg);
        return "";
    }
    qsizetype msgLen = len;

    // Set the tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (unsigned char *) (cipher.data() + cipher.size() - 16)) <= 0) {
        // Handle error
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_free(msg);
        return "";
    }

    // Finalize the decryption
    if (EVP_DecryptFinal_ex(ctx, msg + len, &len) <= 0) {
        // Handle error
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_free(msg);
        return "";
    }
    msgLen += len;

    // Free the context
    EVP_CIPHER_CTX_free(ctx);

    QByteArray tmp;
    tmp.append((char *) msg, msgLen);

    OPENSSL_free(msg);
    // Return the message
    return tmp;
}

unsigned long long checksum0(const QByteArray &data) {
    QMutexLocker ml(&Key::checksum0);
    unsigned long long tmp = 0;
    for (auto i: data)
        tmp += (0x00000000000000FFull & ((unsigned char) i));
    return tmp;
}
int checksum1(const QByteArray &data) {
    QMutexLocker ml(&Key::checksum1);
    int tmp = 0;
    for (auto i: data)
        tmp += i;
    return tmp;
}
QByteArray checksums(const QByteArray &data) {
    QMutexLocker ml(&Key::checksums);

    Dump d;
    d.push(checksum1(data));

    QByteArray b0;
    b0.append(d.get(), (qsizetype) d.size());

    d.clear().push(checksum0(b0 + data));
    QByteArray b1;
    b1.append(d.get(), (qsizetype) d.size());

    return b1 + b0;
}
