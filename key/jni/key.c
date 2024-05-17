#define EXPORT
#include "key.h"
#include <openssl/evp.h>

int genKeyPair(unsigned char *priKey, unsigned char *pubKey) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) return 0;
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -2;
    }
    EVP_PKEY_CTX_free(pctx);
    size_t size = X25519_LEN;
    if (EVP_PKEY_get_raw_public_key(pkey, pubKey, &size) <= 0) {
        EVP_PKEY_free(pkey);
        return -3;
    }
    if (EVP_PKEY_get_raw_private_key(pkey, priKey, &size) <= 0) {
        EVP_PKEY_free(pkey);
        return -4;
    }
    EVP_PKEY_free(pkey);
    return 1;
}

int genSharedKey(unsigned char *priKey, unsigned char *pubKey, unsigned char *sharedKey) {
    // 创建私钥
    EVP_PKEY *thisKey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priKey, X25519_LEN);
    if (!thisKey)return 0;
    // 创建公钥
    EVP_PKEY *peerKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pubKey, X25519_LEN);
    if (!peerKey) {
        EVP_PKEY_free(thisKey);
        return -1;
    }

    // 新建上下文
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(NULL, thisKey, NULL);
    if (!pctx) {
        EVP_PKEY_free(thisKey);
        EVP_PKEY_free(peerKey);
        return -2;
    }

    // 初始化上下文
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(thisKey);
        EVP_PKEY_free(peerKey);
        return -3;
    }

    // 设置对端密钥
    if (EVP_PKEY_derive_set_peer(pctx, peerKey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(thisKey);
        EVP_PKEY_free(peerKey);
        return -4;
    }

    // 生成共享密钥
    size_t size = X25519_LEN;
    if (EVP_PKEY_derive(pctx, sharedKey, &size) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(thisKey);
        EVP_PKEY_free(peerKey);
        return -5;
    }

    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(thisKey);
    EVP_PKEY_free(peerKey);
    return 1;
}

int encryptData(unsigned char *msg, int msgSize, unsigned char *key, unsigned char *IV, unsigned char *cipher) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)return 0;
    // 初始化上下文
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // 设置IV长度
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -2;
    }

    // 设置密钥与IV
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, IV) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -3;
    }

    // 加密消息
    int len = msgSize + IV_LEN;
    if (EVP_EncryptUpdate(ctx, cipher, &len, msg, msgSize) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -4;
    }
    int cipherLen = len;

    // 完成加密
    if (EVP_EncryptFinal_ex(ctx, cipher + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -5;
    }
    cipherLen += len;

    // 追加tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, IV_LEN, cipher + cipherLen) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -6;
    }
    cipherLen += IV_LEN;

    EVP_CIPHER_CTX_free(ctx);
    return cipherLen;
}

int decryptData(unsigned char *cipher, int cipherSize, unsigned char *key, unsigned char *IV, unsigned char *msg) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)return 0;
    // 初始化上下文
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // 设置IV长度
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -2;
    }

    // 设置密钥与IV
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, IV) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -3;
    }

    // 解密数据
    int len = cipherSize - IV_LEN;
    if (EVP_DecryptUpdate(ctx, msg, &len, cipher, cipherSize) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -4;
    }
    int msgLen = len;

    // 设置tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, IV_LEN, cipher + cipherSize - IV_LEN) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -5;
    }

    // 完成解密
    if (EVP_DecryptFinal_ex(ctx, msg + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -6;
    }
    msgLen += len;

    EVP_CIPHER_CTX_free(ctx);
    return msgLen;
}
