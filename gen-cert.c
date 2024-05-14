/* gen-cert
 * 生成X25519公钥证书和私钥文件
 * gen-cert <文件路径> <文本信息> <IP地址> <到期时间>
 * 执行后如果没问题会生成"文件路径.pub"的证书公钥和"文件路径.key"私钥文件
 * 其中"文本信息"必须在15个字节以内, IP地址必须是IPv4或IPv6的地址
 * 到期时间以天位单位
 *
 * 证书文件格式
 *    0 <---------7|8--------> EF
 * 00 |         pub key         |
 * 10 |                         |
 * 20 | start time | valid time |
 * 30 |        text msg        |f
 * 40 |         IP addr         |
 * 其中
 * 00 ~ 1F 为32字节的X25519公钥raw数据
 * 20 ~ 27 为8个字节的证书开始时间, 精确到天; 如何获取? 当前时间戳(精确到秒)/86400, 86400为一天的秒数
 * 28 ~ 2F 为8个字节的证书有效时间, 精确到天
 * 30 ~ 3E 为15个字节的文本信息(如果文本长度不足15字节自动填0以对齐)
 * 3F f为一个字节的IP地址类型, 4表示IPv4, 16表示IPv6; 填写的是IP数字, 例如127.0.0.1的IP数字是2130706433
 * 40 ~ 4F 为16个字节的IP地址(如果是IPv4, 数字只占4个字节, 其余填0; IPv6会把16个字节全部占满)
 * 注意以上数据均为bin数据
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#elif __linux__
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#error 未知的平台
#endif

#define ED25519_LEN 32
const char *pub_suffix = ".pub";

int get_ip_type_and_convert(const char *ip_addr, unsigned char *ip_bin, size_t *ip_len);
int generate_key_pair(unsigned char *pub_key, unsigned char *p_key);

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "%s <file path> <text msg> <IP addr> <valid time>\n", argv[0]);
        return 1;
    }

    // 检查文本
    size_t text_len = strlen(argv[2]);
    if (text_len > 15) {
        fprintf(stderr, "Text message must be within 15 bytes.\n");
        return 1;
    }
    // 检查有效期
    char *end_ptr;
    long long valid_time = strtol(argv[4], &end_ptr, 10);
    if (valid_time <= 0 || *end_ptr != '\0') {
        fprintf(stderr, "Valid time must be a positive number.\n");
        return 1;
    }
    // 转换IP
    unsigned char ip_bin[16] = {0};
    size_t ip_len = 0;
    if (get_ip_type_and_convert(argv[3], ip_bin, &ip_len) <= 0) {
        fprintf(stderr, "Invalid IP address.\n");
        return 1;
    }

    // 生成密钥对
    unsigned char pub_key[ED25519_LEN] = {0};
    unsigned char p_key[ED25519_LEN] = {0};
    if (generate_key_pair(pub_key, p_key) <= 0) {
        fprintf(stderr, "Failed to generate key pair.\n");
        return 1;
    }

    // 获取开始时间
    long long start_time = time(NULL) / 86400; // 以天为单位

    size_t file_path_len = strlen(argv[1]);
    size_t pub_suffix_len = strlen(pub_suffix);
    char *p_key_file_path = argv[1];
    char *pub_key_file_path = malloc(file_path_len + pub_suffix_len + 1);
    memcpy(pub_key_file_path, argv[1], file_path_len);
    memcpy(pub_key_file_path + file_path_len, pub_suffix, pub_suffix_len + 1);
    // 打开文件
    FILE *fp = fopen(pub_key_file_path, "wb");
    if (!fp) {
        fprintf(stderr, "Failed to open %s for writing\n", pub_key_file_path);
        free(pub_key_file_path);
        return 1;
    }
    // 写入公钥
    size_t wrote_size = fwrite(pub_key, 1, ED25519_LEN, fp);
    wrote_size += fwrite((char *) &start_time, 1, 8, fp);
    wrote_size += fwrite((char *) &valid_time, 1, 8, fp);
    wrote_size += fwrite(argv[2], 1, text_len, fp);
    if (text_len < 15) {
        char *fill0 = malloc(15 - text_len);
        for (int i = 0; i < 15 - text_len; i++)fill0[i] = 0;
        wrote_size += fwrite(fill0, 1, 15 - text_len, fp);
        free(fill0);
    }
    wrote_size += fwrite((char *) &ip_len, 1, 1, fp);
    wrote_size += fwrite(ip_bin, 1, 16, fp);
    if (wrote_size != 0x50) {
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

/*
 * get_ip_type_and_convert
 * 该函数将一个IP字符串地址转成对应的IP数字
 * ip_addr为字符串的IP地址, 例如127.0.0.1, ::1
 * ip_bin为目标存储缓存, IPv4有4个字节, IPv6有16个字节
 * ip_len为目标长度, 4个字节为IPv4, 16个字节为IPv6
 * 返回值0表示转换成功, 非0表示失败
 */
int get_ip_type_and_convert(const char *ip_addr, unsigned char *ip_bin, size_t *ip_len) {
#ifdef _WIN32
    int result = InetPton(AF_INET, ip_addr, ip_bin);
    if (result == 1) {
        *ip_len = 4;
        return 1;
    }
    result = InetPton(AF_INET6, ip_addr, ip_bin);
    if (result == 1) {
        *ip_len = 16;
        return 1;
    }
    return 0;
#elif __linux__
    int result = inet_pton(AF_INET, ip_addr, ip_bin);
    if (result == 1) {
        *ip_len = 4;
        return 1;
    }
    result = inet_pton(AF_INET6, ip_addr, ip_bin);
    if (result == 1) {
        *ip_len = 16;
        return 1;
    }
    return 0;
#else
#error 未知的平台
#endif
}

int generate_key_pair(unsigned char *pub_key, unsigned char *p_key) {
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
