/* sign
 * 签名
 * sing <私钥文件> <证书公钥>
 * 执行后如果没问题会生成"证书文件.cert"
 */

#include <stdio.h>
#include <malloc.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>

int readAll(char *file_path, char **data) {
    int size;
    FILE *fp = fopen(file_path, "rb");
    if (fp == NULL)return -1;
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    *data = malloc(size);
    if (*data == NULL) {
        fclose(fp);
        return -2;
    }
    size_t result = fread(*data, 1, size, fp);
    if (result != size) {
        free(*data);
        *data = NULL;
        fclose(fp);
        return -3;
    }
    fclose(fp);
    return size;
}

int sign(unsigned char* message, int msg_len, EVP_PKEY* privkey, unsigned char** signature, size_t* signature_len) {
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        fprintf(stderr, "Error creating EVP_MD_CTX.\n");
        return 0;
    }

    if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, privkey) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        fprintf(stderr, "Error initializing DigestSign.\n");
        return 0;
    }

    if (EVP_DigestSign(md_ctx, NULL, signature_len, message, msg_len) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        fprintf(stderr, "Error signing the size.\n");
        return 0;
    }

    *signature = (unsigned char*)malloc(*signature_len);
    if (!*signature) {
        EVP_MD_CTX_free(md_ctx);
        fprintf(stderr, "Memory allocation failure.\n");
        return 0;
    }

    if (EVP_DigestSign(md_ctx, *signature, signature_len, message, msg_len) <= 0) {
        free(*signature);
        EVP_MD_CTX_free(md_ctx);
        fprintf(stderr, "Error signing the message.\n");
        return 0;
    }

    EVP_MD_CTX_free(md_ctx);
    return 1;
}

char *prepare_sign_file_path(const char *cert_path) {
    char *last_dot = strrchr(cert_path, '.');
    size_t new_path_length = last_dot ? (last_dot - cert_path) + strlen(".cert") + 1 : strlen(cert_path) + strlen(".cert") + 1;
    char *sign_file_path = malloc(new_path_length);
    if (!sign_file_path) return NULL;
    strncpy(sign_file_path, cert_path, last_dot ? last_dot - cert_path : strlen(cert_path));
    sign_file_path[last_dot ? last_dot - cert_path : strlen(cert_path)] = 0;
    strcat(sign_file_path, ".cert");
    return sign_file_path;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "%s <pkey file path> <cert file path>\n", argv[0]);
        return 1;
    }

    unsigned char *pkey_file_data;
    int pkey_file_size = readAll(argv[1], (char **) &pkey_file_data);
    if (pkey_file_size <= 0) {
        free(pkey_file_data);
        perror("Reading private key file failed");
        return 1;
    }

    char *cert_file_data;
    int cert_file_size = readAll(argv[2], &cert_file_data);
    if (cert_file_size <= 0) {
        perror("Reading certificate file failed");
        free(pkey_file_data);
        free(cert_file_data);
        return 1;
    }

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, pkey_file_data, pkey_file_size);
    if (!pkey) {
        perror("Failed to load private key");
        free(pkey_file_data);
        free(cert_file_data);
        return 1;
    }

    unsigned char hash[SHA512_DIGEST_LENGTH];
    if (!SHA512((unsigned char *) cert_file_data, cert_file_size, hash)) {
        perror("Failed to calculate SHA-512 hash of certificate");
        EVP_PKEY_free(pkey);
        free(pkey_file_data);
        free(cert_file_data);
        return 1;
    }

    unsigned char *signature;
    size_t signature_len;
    int ret = sign(hash, SHA512_DIGEST_LENGTH, pkey, &signature, &signature_len);
    if (ret != 1) {
        perror("Signing failed");
        EVP_PKEY_free(pkey);
        free(pkey_file_data);
        free(cert_file_data);
        return 1;
    }

    char *sign_file_path = prepare_sign_file_path(argv[2]);
    if (!sign_file_path) {
        perror("Preparing signature file path failed");
        free(signature);
        EVP_PKEY_free(pkey);
        free(pkey_file_data);
        free(cert_file_data);
        return 1;
    }

    FILE *fp = fopen(sign_file_path, "wb");
    if (!fp) {
        perror("Failed to open signature file for writing");
        free(sign_file_path);
        free(signature);
        EVP_PKEY_free(pkey);
        free(pkey_file_data);
        free(cert_file_data);
        return 1;
    }
    if (fwrite(cert_file_data, 1, cert_file_size, fp) != cert_file_size) {
        perror("Failed to write certificate to file");
        fclose(fp);
        remove(sign_file_path); // 删除未完全写入的签名文件
        free(sign_file_path);
        free(signature);
        EVP_PKEY_free(pkey);
        free(pkey_file_data);
        free(cert_file_data);
        return 1;
    }
    if (fwrite(signature, 1, signature_len, fp) != signature_len) {
        perror("Failed to write signature to file");
        fclose(fp);
        remove(sign_file_path); // 删除未完全写入的签名文件
        free(sign_file_path);
        free(signature);
        EVP_PKEY_free(pkey);
        free(pkey_file_data);
        free(cert_file_data);
        return 1;
    }
    fclose(fp);

    free(signature);
    EVP_PKEY_free(pkey);
    free(pkey_file_data);
    free(cert_file_data);
    free(sign_file_path);
    return 0;
}
