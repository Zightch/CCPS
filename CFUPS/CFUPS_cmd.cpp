#include "CFUPS.h"
#include "key.h"
#include "CFUPS_macro.h"
#include "CFUPSManager.h"

void CFUPS::cmdRC_(const QByteArray &data) { // 已经被CFUPSManager过滤过了, 不用二次判断
    if (cs != -1 || initiative)return; // 连接状态: 未连接, 而且不能是主动连接
    long long time = *(long long *) (data.data() + 3);
    if (!time_(0, time))return; // 时间不正确
    IV = data.mid(11, IV_LEN); // 提取IV
    peerCrt = data.mid(11 + IV_LEN); // 提取对端证书
    if (!verify_()) {
        close("客户端证书验证失败");
        return;
    }
    if (!tryGenKeyPair_()) {
        close("密钥对生成失败");
        return;
    }
    sharedKey.resize(LEN_25519);
    QByteArray priKey = localKey.mid(0, LEN_25519);
    QByteArray pubKey = peerCrt.mid(0, LEN_25519);
    if (GenSharedKey((CUCP) priKey.data(), (CUCP) pubKey.data(), (UCP) sharedKey.data()) <= 0) {
        sharedKey.clear();
        IV.clear();
        close("共享密钥生成失败");
        return;
    }
    auto cdpt = newCDPT_(); // 构建回复数据包
    cdpt->SID = 0;
    cdpt->AID = 0;
    cdpt->cf = (char) 0x43;
    cdpt->data = localCrt;
    cdpt->isNotEncrypt = true;
    if (peerCrt.size() == CRT_LEN || localCrt.size() == CRT_LEN) { // 如果任意一方使用证书
        unsigned short sexticTimingTime = (retryNum + 1) * timeout;
        if (sexticTimingTime > 30000)sexticTimingTime = 30000;
        cdpt->data.append((char *) &sexticTimingTime, sizeof(sexticTimingTime));
        sexticTiming.setInterval(sexticTimingTime);
    }
    sendBufLv1.append(cdpt);
    OID = 0;
    cs = 0; // 半连接
}

void CFUPS::cmdACK_(bool NA, const QByteArray &data) {
    if (!NA) return;
    if (data.size() != 3)return;
    unsigned short AID = (*(unsigned short *) (data.data() + 1));
    if (cs == 0) { // 如果是半连接状态
        if (AID == 0 && !initiative) {
            sendWnd[AID]->stop();
            if (peerCrt.size() == CRT_LEN || localCrt.size() == CRT_LEN) { // 如果任意一方使用证书
                cs = 1; // 开始6次握手
                sexticTiming.start();
                localCrt.clear();
                localKey.clear();
                if (!tryGenKeyPair_()) {
                    close("6次握手密钥对生成失败");
                    return;
                }
                sendBufLv2.append(localCrt); // 准备数据
            } else { // 连接成功
                cs = 2;
                cm->cfupsConnected_(this);
                hbt.start(hbtTime);
            }
        }
    } else if (sendWnd.contains(AID)) sendWnd[AID]->stop();
}

void CFUPS::cmdRC_ACK_(bool RT, bool UD, const QByteArray &data) {
    if (cs == 0 && initiative && UD && data.size() > 13) {
        unsigned short SID = *(unsigned short *) (data.data() + 1);
        long long time = *(long long *) (data.data() + 3);
        unsigned short AID = *(unsigned short *) (data.data() + 11);
        if (SID != 0 || AID != 0) return;
        if (!time_(SID, time))return;
        ID = 1;
        OID = 0;
        delete sendWnd[0];
        sendWnd.remove(0);
        peerCrt = data.mid(13);
        if (peerCrt.size() != CRT_LEN && peerCrt.size() != LEN_25519 && peerCrt.size() != CRT_LEN + 2 && peerCrt.size() != LEN_25519 + 2) {
            cs = 3;
            sharedKey.clear();
            IV.clear();
            close("证书长度不正确");
            return;
        }
        if (peerCrt.size() == LEN_25519 + 2 || peerCrt.size() == CRT_LEN + 2) { // 2个字节的时间
            auto tmp = peerCrt.mid(peerCrt.size() - 2, 2);
            unsigned short sexticTimingTime = *(unsigned short *) tmp.data();
            if (sexticTimingTime > 30000)sexticTimingTime = 30000;
            peerCrt = peerCrt.mid(0, peerCrt.size() - 2);
            sexticTiming.setInterval((int) sexticTimingTime);
        }
        if (!verify_()) {
            cs = 3;
            sharedKey.clear();
            IV.clear();
            close("服务器证书验证失败");
            return;
        }
        sharedKey.resize(LEN_25519);
        QByteArray priKey = localKey.mid(0, LEN_25519);
        QByteArray pubKey = peerCrt.mid(0, LEN_25519);
        if (GenSharedKey((CUCP) priKey.data(), (CUCP) pubKey.data(), (UCP) sharedKey.data()) <= 0) {
            sharedKey.clear();
            IV.clear();
            cs = 3;
            close("共享密钥生成失败");
            return;
        }
        NA_ACK_(0);
        if (peerCrt.size() == CRT_LEN || localCrt.size() == CRT_LEN) { // 如果任意一端使用证书
            cs = 1;
            sexticTiming.start();
            localCrt.clear();
            localKey.clear();
            if (!tryGenKeyPair_()) {
                close("6次握手密钥对生成失败");
                return;
            }
            sendBufLv2.append(localCrt); // 准备数据
        } else { // 连接成功
            cs = 2;
            cm->cfupsConnected_(this);
            hbt.start(hbtTime);
        }
    } else if (RT)NA_ACK_(0);
}

void CFUPS::cmdC_(bool NA, bool UD, const QByteArray &data) {
    if (!NA) return; // NA必须有
    QByteArray userData;
    if (UD)userData = data.mid(1);
    close(userData);
}

void CFUPS::cmdH_(bool RT, const QByteArray &data) {
    if (cs != 2 || data.size() != 11)return;
    unsigned short SID = (*(unsigned short *) (data.data() + 1));
    long long time = *(long long *) (data.data() + 3);
    if (!time_(SID, time))return;
    NA_ACK_(SID);
    if (SID == OID + 1) {
        OID = SID;
        hbt.stop();
        hbt.start(hbtTime);
    } else if (!RT)
        close("心跳包ID不正确");
}
