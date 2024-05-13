/* genCAKey
 * 生成ED25519的密钥对
 * genCAKey <文件路径>
 * 执行后如果没问题会生成"文件路径"的私钥文件和"文件路径.pub"公钥文件
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

int main(int argc, char **argv) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    FILE *fp = NULL;
    unsigned char *privkey_data = NULL, *pubkey_data = NULL;

    if (argc != 2) {
        fprintf(stderr, "%s <file path>\n", argv[0]);
        goto cleanup;
    }

    char *file_path = argv[1];
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!pctx) {
        fprintf(stderr, "Error creating EVP_PKEY context\n");
        goto cleanup;
    }
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        fprintf(stderr, "Error initializing key generation\n");
        goto cleanup;
    }
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        fprintf(stderr, "Error generating the ED25519 key pair\n");
        goto cleanup;
    }

    // Save private key in binary format
    fp = fopen(file_path, "wb");
    if (!fp) {
        fprintf(stderr, "Unable to open file %s\n", file_path);
        goto cleanup;
    }
    size_t privkey_len;
    if (EVP_PKEY_get_raw_private_key(pkey, NULL, &privkey_len) <= 0) {
        fprintf(stderr, "Error getting private key size\n");
        goto close_fp;
    }
    privkey_data = malloc(privkey_len);
    if (!privkey_data) {
        fprintf(stderr, "Memory allocation failed for private key data\n");
        goto close_fp;
    }
    if (EVP_PKEY_get_raw_private_key(pkey, privkey_data, &privkey_len) <= 0) {
        fprintf(stderr, "Error getting private key data\n");
        goto free_privkey_data;
    }
    if (fwrite(privkey_data, 1, privkey_len, fp) != privkey_len) {
        fprintf(stderr, "Error writing private key data to file\n");
        goto free_privkey_data;
    }

    // Save public key in binary format
    char pub_file_path[100];
    snprintf(pub_file_path, sizeof(pub_file_path), "%s.pub", file_path);
    fp = fopen(pub_file_path, "wb");
    if (!fp) {
        fprintf(stderr, "Unable to open file %s\n", pub_file_path);
        goto free_privkey_data_and_close_fp;
    }
    size_t pubkey_len;
    if (EVP_PKEY_get_raw_public_key(pkey, NULL, &pubkey_len) <= 0) {
        fprintf(stderr, "Error getting public key size\n");
        goto close_pub_fp;
    }
    pubkey_data = malloc(pubkey_len);
    if (!pubkey_data) {
        fprintf(stderr, "Memory allocation failed for public key data\n");
        goto close_pub_fp;
    }
    if (EVP_PKEY_get_raw_public_key(pkey, pubkey_data, &pubkey_len) <= 0) {
        fprintf(stderr, "Error getting public key data\n");
        goto free_pubkey_data;
    }
    if (fwrite(pubkey_data, 1, pubkey_len, fp) != pubkey_len) {
        fprintf(stderr, "Error writing public key data to file\n");
        goto free_pubkey_data;
    }

    cleanup:
    free(privkey_data);
    free(pubkey_data);
    if (fp) {
        fclose(fp);
    }
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return 0;

    close_pub_fp:
    fclose(fp);
    free_pubkey_data:
    free(pubkey_data);
    goto free_privkey_data_and_close_fp;

    close_fp:
    fclose(fp);
    free_privkey_data:
    free(privkey_data);
    free_privkey_data_and_close_fp:
    if (fp) {
        fclose(fp);
    }
    goto cleanup;
}
