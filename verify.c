/* verify
 * 使用公钥对证书和签名进行验签
 * verify <公钥文件> <证书文件>
 * 执行后如果没问题会输出OK
 * 验签失败输出Fail
 */

#include <stdio.h>
#include <malloc.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

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
        fprintf(stderr, "%s <pubkey file path> <cert file path>\n", argv[0]);
        return 1;
    }

    unsigned char *pub_key;
    int pub_key_size = readAll(argv[1], (char **) &pub_key);
    if (pub_key_size <= 0) {
        perror("Reading private key file failed");
        if (pub_key_size == -3)free(pub_key);
        return 1;
    }

    char *cert_file_data;
    int cert_file_size = readAll(argv[2], &cert_file_data);
    if (cert_file_size != 144) {
        perror("Reading certificate file failed");
        free(pub_key);
        if (cert_file_size == -3)free(cert_file_data);
        return 1;
    }

    unsigned char *sign_file_data = (unsigned char *) (cert_file_data + 0x50);

    unsigned char hash[SHA512_DIGEST_LENGTH];
    if (!SHA512((unsigned char *) cert_file_data, 0x50, hash)) {
        perror("Failed to calculate SHA-512 hash of certificate");
        free(pub_key);
        free(cert_file_data);
        return 1;
    }

    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub_key, pub_key_size);
    if (!pkey) {
        perror("Failed to load public key");
        free(pub_key);
        free(cert_file_data);
        return 1;
    }

    int ret = verify(pkey, hash, SHA512_DIGEST_LENGTH, sign_file_data, cert_file_size - 0x50);

    if (ret == 1)printf("OK\n");
    else if (ret == 0)printf("Fail\n");
    else fprintf(stderr, "An error occurred during visa verification\n");

    EVP_PKEY_free(pkey);
    free(pub_key);
    free(cert_file_data);
    return 0;
}
