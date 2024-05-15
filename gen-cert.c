/* gen-cert
 * 生成公钥证书和私钥文件
 * gen-cert <文件路径> <文本信息> <IP地址> <到期时间>
 * 执行后如果没问题会生成"文件路径.pub"的证书公钥和"文件路径.key"私钥文件
 *
 * 证书文件格式
 *    0 <-3|4--7|8------> EF
 * 00 |       X25519       |
 * 10 |      pub key       |
 * 20 |      ED25519       |
 * 30 |      pub key       |
 * 40 | st | vt | text msg |
 * 50 |                    |
 * 60 |                   |f
 * 70 |      IP addr       |
 * 其中
 * 00 ~ 1F X25519 pub key  为32字节的X25519公钥raw数据, 用于密钥交换
 * 20 ~ 3F ED25519 pub key 为32字节的ED25519公钥raw数据, 用于签名; 当该证书为CA证书时, 有这部分数据, 否则32个字节全是0
 * 40 ~ 43 st       为4个字节的证书开始时间, 精确到天; 如何获取? 当前时间戳(精确到秒)/86400, 86400为一天的秒数
 * 44 ~ 47 vt       为4个字节的证书有效时间, 精确到天
 * 48 ~ 6E text msg 为39个字节的文本信息(如果文本长度不足39字节自动填0以对齐)
 * 6F      f        为1个字节的IP地址类型, 4表示IPv4, 16表示IPv6; 填写的是IP数字, 例如127.0.0.1的IP数字是2130706433
 * 70 ~ 7F IP addr  为16个字节的IP地址(如果是IPv4, 数字只占4个字节, 其余填0; IPv6会把16个字节全部占满)
 * 总长度128字节
 * 注意以上数据均为bin数据
 *
 * 私钥文件格式与证书相同, 只有00 ~ 3F数据, 没有别的内容
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

#define LEN_25519 32
#define TEXT_MSG_LEN 39
#define CERT_LEN 0x80
const char *pub_suffix = ".pub";

int get_ip_type_and_convert(const char *ip_addr, unsigned char *ip_bin, size_t *ip_len);
int generate_key_pair(unsigned char *pub_key, unsigned char *p_key, int id);

int main(int argc, char **argv) {
    if (4 > argc || argc > 6) {
        fprintf(
                stderr,
                "%s <file path> <text msg> <valid time>\n"
                "%s <file path> <text msg> <valid time> [CA]\n"
                "%s <file path> <text msg> <valid time> [IP addr]\n"
                "%s <file path> <text msg> <valid time> [CA] [IP addr]\n\n"
                "CA is true or false, default is false\n",
                argv[0], argv[0], argv[0], argv[0]
        );
        return 1;
    }

    // 检查文本
    size_t text_len = strlen(argv[2]);
    if (text_len > TEXT_MSG_LEN) {
        fprintf(stderr, "Text message must be within %d bytes.\n", TEXT_MSG_LEN);
        return 1;
    }

    // 获取开始时间
    unsigned start_time = time(NULL) / 86400; // 以天为单位
    // 检查有效期
    char *end_ptr;
    long long tmp = strtol(argv[3], &end_ptr, 10);
    unsigned int valid_time = start_time + tmp;
    if (valid_time <= 0 || *end_ptr != '\0') {
        fprintf(stderr, "Valid time must be a positive number.\n");
        return 1;
    }

    int CA = 0;
    unsigned char ip_bin[16] = {0};
    size_t ip_len = 0;
    if (argc == 5) {
        if (strcmp(argv[4], "false") == 0)CA = 0;
        else if (strcmp(argv[4], "true") == 0)CA = 1;
        else if (get_ip_type_and_convert(argv[4], ip_bin, &ip_len) <= 0) {
            fprintf(stderr, "Invalid 4th parameter.\n");
            return 1;
        }
    }
    if (argc == 6) {
        if (strcmp(argv[4], "false") == 0)CA = 0;
        else if (strcmp(argv[4], "true") == 0)CA = 1;
        else {
            fprintf(stderr, "Valid time must be true or false.\n");
            return 1;
        }
        if (get_ip_type_and_convert(argv[5], ip_bin, &ip_len) <= 0) {
            fprintf(stderr, "Invalid IP address.\n");
            return 1;
        }
    }

    // 生成密钥对
    unsigned char x25519_pub_key[LEN_25519] = {0};
    unsigned char x25519_p_key[LEN_25519] = {0};
    if (generate_key_pair(x25519_pub_key, x25519_p_key, EVP_PKEY_X25519) <= 0) {
        fprintf(stderr, "Failed to generate key pair.\n");
        return 1;
    }

    unsigned char ed25519_pub_key[LEN_25519] = {0};
    unsigned char ed25519_p_key[LEN_25519] = {0};
    if (CA == 1) {
        if (generate_key_pair(ed25519_pub_key, ed25519_p_key, EVP_PKEY_ED25519) <= 0) {
            fprintf(stderr, "Failed to generate key pair.\n");
            return 1;
        }
    }

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

    size_t wrote_size = 0;
    wrote_size += fwrite(x25519_pub_key, 1, LEN_25519, fp); // 写入32字节x25519公钥
    wrote_size += fwrite(ed25519_pub_key, 1, LEN_25519, fp); // 写入32字节ed25519公钥
    wrote_size += fwrite((char *) &start_time, 1, 4, fp); // 写入4字节开始时间
    wrote_size += fwrite((char *) &valid_time, 1, 4, fp); // 写入4字节到期时间
    wrote_size += fwrite(argv[2], 1, text_len, fp); // 写入文本信息
    if (text_len < TEXT_MSG_LEN) { // 不足补0
        char *fill0 = malloc(TEXT_MSG_LEN - text_len);
        for (int i = 0; i < TEXT_MSG_LEN - text_len; i++)fill0[i] = 0;
        wrote_size += fwrite(fill0, 1, TEXT_MSG_LEN - text_len, fp);
        free(fill0);
    }
    wrote_size += fwrite((char *) &ip_len, 1, 1, fp); // 写入IP类型
    wrote_size += fwrite(ip_bin, 1, 16, fp); // 写入IP
    if (wrote_size != CERT_LEN) { // 检查写入情况
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
    wrote_size = 0;
    wrote_size += fwrite(x25519_p_key, 1, LEN_25519, fp);
    wrote_size += fwrite(ed25519_p_key, 1, LEN_25519, fp);
    if (wrote_size != LEN_25519 * 2) {
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
    size_t tmp = *ip_len;
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
#else
#error 未知的平台
#endif
    for (int i = 0; i < tmp; i++)ip_bin[i] = 0;
    *ip_len = 0;
    return 0;
}

int generate_key_pair(unsigned char *pub_key, unsigned char *p_key, int id) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(id, NULL);
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
    size_t size = LEN_25519;
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
