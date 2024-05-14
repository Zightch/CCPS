/* gen-ca-key
 * 生成ED25519的密钥对
 * gen-ca-key <文件路径>
 * 执行后如果没问题会生成"文件路径"的私钥文件和"文件路径.pub"公钥文件
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#define ED25519_LEN 32
const char *pub_suffix = ".pub";

int generate_key_pair(unsigned char *pub_key, unsigned char *p_key) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
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
    size_t size = ED25519_LEN;
    if (EVP_PKEY_get_raw_public_key(pkey, pub_key, &size) <= 0) {
        EVP_PKEY_free(pkey);
        return -3;
    }
    if (EVP_PKEY_get_raw_private_key(pkey, p_key, &size) <= 0) {
        EVP_PKEY_free(pkey);
        return -4;
    }
    EVP_PKEY_free(pkey);
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "%s <file path>\n", argv[0]);
        return 1;
    }

    unsigned char p_key[ED25519_LEN], pub_key[ED25519_LEN];
    if (generate_key_pair(pub_key, p_key) <= 0) {
        fprintf(stderr, "Failed to generate key pair.\n");
        return 1;
    }

    size_t file_path_len = strlen(argv[1]);
    size_t pub_suffix_len = strlen(pub_suffix);
    char *p_key_file_path = argv[1];
    char *pub_key_file_path = malloc(file_path_len + pub_suffix_len + 1);
    memcpy(pub_key_file_path, argv[1], file_path_len);
    memcpy(pub_key_file_path + file_path_len, pub_suffix, pub_suffix_len + 1);

    FILE *fp = fopen(pub_key_file_path, "wb");
    if (!fp) {
        fprintf(stderr, "Failed to open %s for writing\n", pub_key_file_path);
        free(pub_key_file_path);
        return 1;
    }
    if (fwrite(pub_key, 1, ED25519_LEN, fp) != ED25519_LEN) {
        fprintf(stderr, "Failed to write public key to file");
        fclose(fp);
        remove(pub_key_file_path);
        free(pub_key_file_path);
        return 1;
    }
    fclose(fp);
    free(pub_key_file_path);

    fp = fopen(p_key_file_path, "wb");
    if (!fp) {
        fprintf(stderr, "Failed to open %s for writing\n", p_key_file_path);
        return 1;
    }
    if (fwrite(p_key, 1, ED25519_LEN, fp) != ED25519_LEN) {
        fprintf(stderr, "Failed to write private key to file");
        fclose(fp);
        remove(p_key_file_path);
        return 1;
    }
    fclose(fp);

    return 0;
}
