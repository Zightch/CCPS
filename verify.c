/* verify
 * 使用公钥对证书和签名进行验签
 * verify <验证证书文件路径> <被验证证书文件路径>
 * 执行后如果没问题会输出OK
 * 验签失败输出Fail
 */

#include <stdio.h>
#include <malloc.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define LEN_25519 32
#define CERT_LEN 0x80
#define SIGN_LEN 64

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

int verify(EVP_PKEY *pkey, unsigned char *message, size_t msg_len, unsigned char *sign, size_t sig_len) {
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        fprintf(stderr, "Error creating EVP_MD_CTX.\n");
        return 0;
    }
    if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) <= 0) {
        fprintf(stderr, "Error init verify.\n");
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }
    int result = EVP_DigestVerify(md_ctx, sign, sig_len, message, msg_len);
    EVP_MD_CTX_free(md_ctx);
    return result;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "%s <verify cert file path> <verified cert file path>\n", argv[0]);
        return 1;
    }

    unsigned char *verify_cert;
    int verify_cert_size = readAll(argv[1], (char **) &verify_cert);
    if (verify_cert_size != CERT_LEN + SIGN_LEN) {
        fprintf(stderr, "Reading verify cert file failed");
        if (verify_cert_size == -3)free(verify_cert);
        return 1;
    }

    char *cert_file_data;
    int cert_file_size = readAll(argv[2], &cert_file_data);
    if (cert_file_size != CERT_LEN + SIGN_LEN) {
        fprintf(stderr, "Reading certificate file failed");
        free(verify_cert);
        if (cert_file_size == -3)free(cert_file_data);
        return 1;
    }

    int CA = 0;
    for (int i = LEN_25519; i < LEN_25519 * 2; i++)
        if (verify_cert[i] == 0)CA++;
    if (CA == LEN_25519)CA = 0;
    else CA = 1;
    if (CA == 0) {
        fprintf(stderr, "The verify cert is not CA");
        free(verify_cert);
        free(cert_file_data);
        return 1;
    }

    unsigned char *sign_file_data = (unsigned char *) (cert_file_data + CERT_LEN);

    unsigned char hash[SHA512_DIGEST_LENGTH];
    if (!SHA512((unsigned char *) cert_file_data, CERT_LEN, hash)) {
        fprintf(stderr, "Failed to calculate SHA-512 hash of certificate");
        free(verify_cert);
        free(cert_file_data);
        return 1;
    }

    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, verify_cert + LEN_25519, LEN_25519);
    if (!pkey) {
        fprintf(stderr, "Failed to load public key");
        free(verify_cert);
        free(cert_file_data);
        return 1;
    }

    int ret = verify(pkey, hash, SHA512_DIGEST_LENGTH, sign_file_data, cert_file_size - CERT_LEN);

    if (ret == 1)printf("OK\n");
    else if (ret == 0)printf("Fail\n");
    else fprintf(stderr, "An error occurred during visa verification\n");

    EVP_PKEY_free(pkey);
    free(verify_cert);
    free(cert_file_data);
    return 0;
}
