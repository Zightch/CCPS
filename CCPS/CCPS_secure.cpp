#include "CCPS.h"
#include "key.h"
#include "CCPS_macro.h"
#include <QDateTime>

bool CCPS::tryGenKeyPair_() {
    if (localCrt.isEmpty()) { // 如果没有使用证书
        localCrt.resize(LEN_25519);
        localKey.resize(LEN_25519);
        return GenKeyPair((UCP) localKey.data(), (UCP) localCrt.data()) == 1;
    }
    return true;
}

bool CCPS::verify_() {
    if (!CA.isEmpty() && peerCrt.size() != CRT_LEN)return false; // 如果我有CA但是对方没有发证书
    if (peerCrt.size() != CRT_LEN)return true; // 验证证书合法性
    unsigned int startTime = *(unsigned int *) (peerCrt.data() + START_TIME_INDEX);
    unsigned int endTime = *(unsigned int *) (peerCrt.data() + END_TIME_INDEX);
    unsigned int currTime = QDateTime::currentSecsSinceEpoch() / 86400;
    if (startTime > currTime || currTime > endTime)return false; // 证书过期

    unsigned char f = peerCrt[IP_FLAGS_INDEX];
    if ((f != 0 && initiative)) { // 如果IP flags有数据并且我是主动连接的, 验证IP
        QByteArray IPData;
        IPData.resize(16);
        if (f != 4 && f != 16)return false; // IP flags不合法
        if (f == 4 && IP.protocol() != QHostAddress::IPv4Protocol)return false; // 协议对不上
        if (f == 16 && IP.protocol() != QHostAddress::IPv6Protocol)return false; // 协议对不上
        if (f == 4)*((unsigned int *) IPData.data()) = IP.toIPv4Address();
        if (f == 16) {
            Q_IPV6ADDR ipv6 = IP.toIPv6Address();
            for (int i = 0; i < 16; i++)
                IPData[i] = (char) ipv6[i];
        }
        if (IPData != peerCrt.mid(IP_FLAGS_INDEX + 1, 16))return false; // IP不匹配
    }

    if (CA.isEmpty())return true; // 忽略CA验签
    QByteArray pubKey = CA.mid(LEN_25519, LEN_25519);
    QByteArray crtContent = peerCrt.mid(0, CRT_LEN - SIGN_LEN); // 证书内容
    QByteArray sign = peerCrt.mid(CRT_LEN - SIGN_LEN); // 签名数据
    QByteArray sha512;
    sha512.resize(SHA521_LEN);
    if (Sha512((CUCP) crtContent.data(), (int) crtContent.size(), (UCP) sha512.data()) <= 0)
        return false; // 计算SHA512失败
    return Verify((CUCP) pubKey.data(), (CUCP) sha512.data(), (int) sha512.size(), (CUCP) sign.data(), (int) sign.size()) == 1;
}
