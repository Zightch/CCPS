#include "CCPS.h"
#include "CCPSManager.h"
#include "tools/Dump.h"
#include "tools/Key.h"
#include <QDateTime>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

CCPS::CCPS(QObject *parent, const QHostAddress&IP, unsigned short p) : QObject(parent), IP(IP), port(p) {
    cm = ((CCPSManager *) parent);
    connect(this, &CCPS::procS_, this, &CCPS::procF_, Qt::QueuedConnection);
    connect(&hbt, &QTimer::timeout, this, [&]() {
        if (cs != 1) return;
        auto *cdpt = new CDPT(this);
        cdpt->cf = 0x05;
        cdpt->SID = ID + sendBuf.size() + sendWnd.size();
        transmitShunt_(cdpt);
        updateWnd_();
    });
}

void CCPS::close(const QByteArray &data) {
    if (cs == 1) {
        auto *cdpt = new CDPT(this);
        cdpt->cf = 0x24;
        if (!data.isEmpty()) {
            cdpt->cf |= 0x40;
            cdpt->data = data;
        }
        sendPackage_(cdpt);
        EVP_PKEY_free((EVP_PKEY *) key);
        key = nullptr;
        sharedKey.clear();
        cs = -1;
    }
    readBuf.append(data);
    for (const auto &i: sendWnd)
        i->stop();
    sendWnd.clear();
    for (const auto &i: sendBuf)
        i->stop();
    sendBuf.clear();
    recvWnd.clear();
    hbt.stop();
    emit disconnected(data);
}

void CCPS::procF_(const QByteArray &data) {
    auto dataC = data.data();
    auto dataSize = data.size();

    //检查校验和
    {
        auto c0 = *(unsigned long long *) dataC;
        auto b = QByteArray::fromRawData(dataC + 8, dataSize - 8);
        if (c0 != checksum0(b))//如果无符号校验和不匹配
            return;
        auto c1 = *(int *) (dataC + 8);
        b = QByteArray::fromRawData(dataC + 12, dataSize - 12);
        if (c1 != checksum1(b))//如果有符号校验和不匹配
            return;
    }
    //校验和通过

    dataC += 12;
    dataSize -= 12;
    QByteArray msg;
    if (cs == 1 || ((!initiative) && (cs == 0))) {
        msg.append(dataC, dataSize);
        msg = decryptData(sharedKey, IV, msg);
        if (msg.isEmpty())
            return;
        dataC = msg.data();
        dataSize = msg.size();
    }

    //检查SHA-256
    {
        unsigned long long s256t[4] = {0};//自己计算的SHA-256
        auto s256p = (unsigned long long *) dataC;//对方给的-SHA256
        SHA256((unsigned char *) (dataC + 32), dataSize - 32, (unsigned char *) s256t);
        if (s256t[0] != s256p[0] || s256t[1] != s256p[1] || s256t[2] != s256p[2] || s256t[3] != s256p[3])
            return;
    }
    //SHA-256通过
    dataC += 32;
    dataSize -= 32;

    unsigned char cf = dataC[0];

    bool UDL = ((cf >> 7) & 0x01);
    bool UD = ((cf >> 6) & 0x01);//包含用户数据
    bool NA = ((cf >> 5) & 0x01);//无需应答
    bool RT = ((cf >> 4) & 0x01);//重发包
    auto cmd = (unsigned char) (cf & (unsigned char) 0x07);

    if (!(NA && RT)) {
        if (1 <= cmd && cmd <= 5 && !UDL) {
            switch (cmd) {
                case 1: {
                    if (UD && dataSize == 51 && cs == -1 && key == nullptr && sharedKey.size() != 32 && !RT) {
                        key = genX25519Key();
                        QByteArray peerPubKey = QByteArray::fromRawData(dataC + 3, 32);
                        sharedKey = genSharedKey(key, peerPubKey);
                        if (sharedKey.isEmpty())
                            break;
                        for (int i = 0; i < 16; i++)
                            IV[i] = dataC[i + 35];
                        auto *tmp = new CDPT(this);
                        tmp->SID = 0;
                        tmp->AID = 0;
                        tmp->cf = 0x43;
                        tmp->data = getPubKey(key);
                        transmitShunt_(tmp);
                        OID = 0;
                        cs = 0;//半连接
                        initiative = false;
                    }
                    break;
                }
                case 2: {
                    if (!NA)
                        break;
                    auto AID = (*(unsigned short *) (dataC + 1));
                    if (AID == 0 && cs == 0 && UD && dataSize == 35) {
                        auto peerSharedKey = QByteArray::fromRawData(dataC + 3, 32);
                        cs = 1;
                        if (sharedKey != peerSharedKey)
                            close();
                        else emit connected_();
                    }
                    if (sendWnd.count(AID) == 1)
                        sendWnd[AID]->stop();
                    break;
                }
                case 3: {
                    if (ID == 0 && OID == 65535 && UD && cs == 0 && key != nullptr && dataSize == 37) {
                        auto SID = (*(unsigned short *) (dataC + 1));
                        auto AID = (*(unsigned short *) (dataC + 3));
                        if (SID != 0 || AID != 0)
                            break;

                        if (sharedKey.isEmpty()) {
                            auto peerPubKey = QByteArray::fromRawData(dataC + 5, 32);
                            sharedKey = genSharedKey(key, peerPubKey);
                            if (sharedKey.isEmpty())
                                break;
                        }

                        ID = 1;
                        OID = 0;
                        cs = 1;
                        delete sendWnd[0];
                        sendWnd.remove(0);
                        emit connected_();
                        hbt.start(hbtTime);
                        NA_ACK(0, sharedKey);
                    }
                    break;
                }
                case 4: {
                    if (!NA)
                        break;

                    QByteArray userData;
                    if (UD)
                        userData.append(dataC + 1, dataSize - 1);
                    EVP_PKEY_free((EVP_PKEY *) key);
                    key = nullptr;
                    sharedKey.clear();
                    readBuf.append(userData);
                    for (const auto &i: sendWnd)
                        i->stop();
                    sendWnd.clear();
                    for (const auto &i: sendBuf)
                        i->stop();
                    sendBuf.clear();
                    recvWnd.clear();
                    hbt.stop();
                    cs = -1;
                    emit disconnected(userData);
                    break;
                }
                case 5: {
                    if (cs != 1)
                        break;
                    auto SID = (*(unsigned short *) (dataC + 1));
                    NA_ACK(SID);
                    if (SID == OID + 1) {
                        OID = SID;
                        hbt.stop();
                        hbt.start(hbtTime);
                    }
                    break;
                }
                default:
                    break;
            }
        } else {
            if (!NA) {//需要回复
                auto SID = (*(unsigned short *) (dataC + 1));
                NA_ACK(SID);
                if (UD) {//有用户数据
                    //创建一个字节数组来存储用户数据
                    QByteArray userData;
                    //从数据包中提取用户数据, 跳过前三个字节的头部信息
                    userData.append(dataC + 3, dataSize - 3);
                    //如果是重发包, 并且接收窗口中已经有该数据, 则不需要再次存储
                    if (!RT || !recvWnd.contains(SID)) (recvWnd[SID] = {cf, SID, userData});
                }
            } else if (UD) {//有用户数据
                QByteArray userData;
                userData.append(dataC + 1, dataSize - 1);
                readBuf.append(userData);
                emit readyRead();
            }
        }
    }
    updateWnd_();
}

void CCPS::sendNow(const QByteArray &data) {
    if (cs != 1) return;
    auto *tmp = new CDPT(this);
    tmp->data = data;
    tmp->cf = 0x60;
    transmitShunt_(tmp);
    updateWnd_();
}

void CCPS::send(const QByteArray &data) {
    if (cs != 1) return;
    if (data.size() <= dataBlockSize) {
        auto *tmp = new CDPT(this);
        tmp->data = data;
        tmp->cf = 0x40;
        tmp->SID = ID + sendBuf.size() + sendWnd.size();
        transmitShunt_(tmp);
    } else {
        QByteArrayList dataBlock;
        QByteArray i = data;
        while (!i.isEmpty()) {
            unsigned short dbs = dataBlockSize;
            if (i.size() <= dataBlockSize)
                dbs = i.size();
            QByteArray tmp;
            tmp.append(i, dbs);
            dataBlock.append(tmp);
            tmp = i;
            i.clear();
            i.append(tmp.data() + dbs, tmp.size() - dbs);
        }
        if (dataBlock.size() <= 65534) {
            auto baseID = sendBuf.size() + sendWnd.size();
            for (auto j = 0; j < dataBlock.size(); j++) {
                auto *cdpt = new CDPT(this);
                cdpt->data = dataBlock[(qsizetype) j];
                cdpt->SID = ID + baseID + j;
                if (j != dataBlock.size() - 1)
                    cdpt->cf = 0xC0;
                else
                    cdpt->cf = 0x40;
                transmitShunt_(cdpt);
            }
        } else
            throw "数据内容超过最大连续发送大小";
    }
    updateWnd_();
}

bool CCPS::hasData() const {
    return !readBuf.empty();
}

QByteArray CCPS::read() {
    if (readBuf.empty())throw "没有数据可读";
    QByteArray tmp = readBuf.first();
    readBuf.pop_front();
    return tmp;
}

void CCPS::setDataBlockSize(unsigned short us) {
    if (us >= 65470)
        dataBlockSize = 65470;
    else dataBlockSize = us;
}

void CCPS::setHBTTime(unsigned short time) {
    hbtTime = time;
    if (cs == 1) {
        hbt.stop();
        hbt.start(hbtTime);
    }
}

QHostAddress CCPS::getIP() const {
    return IP;
}

unsigned short CCPS::getPort() const {
    return port;
}

void CCPS::connect_() {
    if (cs != -1)return;
    if (key != nullptr || (!sharedKey.isEmpty()))
        return;

    key = genX25519Key();
    if (key == nullptr) {
        emit disconnected("密钥对生成失败");
        return;
    }

    auto pubKey = getPubKey(key);
    if (pubKey.isEmpty()) {
        emit disconnected("公钥获取失败");
        return;
    }

    RAND_bytes(IV, 16);

    auto *tmp = new CDPT(this);
    tmp->SID = 0;
    tmp->cf = 0x41;
    tmp->data = pubKey;
    tmp->data.append((char *) IV, 16);
    transmitShunt_(tmp);
    cs = 0;
    initiative = true;
    updateWnd_();
}

CCPS::~CCPS() {
    close();
    cm = nullptr;
    readBuf.clear();
}

void CCPS::sendTimeout_() {
    auto *cdpt = (CDPT *) sender();
    if (cdpt->retryNum < retryNum) {
        cdpt->retryNum++;
        cdpt->cf |= 0x10;
        sendWnd.remove(cdpt->SID);
        transmitShunt_(cdpt);
    } else {
        EVP_PKEY_free((EVP_PKEY *) key);
        key = nullptr;
        sharedKey.clear();
        readBuf.append("对方应答超时");
        for (const auto &i: sendWnd)
            i->stop();
        sendWnd.clear();
        for (const auto &i: sendBuf)
            i->stop();
        sendBuf.clear();
        recvWnd.clear();
        hbt.stop();
        cs = -1;
        emit disconnected("对方应答超时");
    }
    updateWnd_();
}

void CCPS::sendPackage_(CDPT *cdpt) {
    Dump d0;
    d0.push(cdpt->cf);
    auto cmd = (unsigned char) (cdpt->cf & 0x07);
    bool NA = (cdpt->cf >> 5) & 0x01;
    bool UD = (cdpt->cf >> 6) & 0x01;
    if (!NA) d0.push(cdpt->SID);
    if ((cmd == 2) || (cmd == 3)) d0.push(cdpt->AID);
    if (UD) d0.push(cdpt->data, cdpt->data.size());

    unsigned char sha256C[32] = {0};
    SHA256((unsigned char *) d0.get(), d0.size(), sha256C);
    QByteArray inner;//内部数据(SHA256 + cf等数据)
    inner.append((const char *) sha256C, 32);
    inner.append(d0.get(), (qsizetype) d0.size());

    if (cmd != 1 && cmd != 3)
        inner = encryptData(sharedKey, IV, inner);

    QByteArray total = checksums(inner) + inner;//整个数据包的数据

    cm->sendF_(IP, port, total);
    if (!NA) {
        disconnect(cdpt, &CDPT::timeout, this, &CCPS::sendTimeout_);
        connect(cdpt, &CDPT::timeout, this, &CCPS::sendTimeout_);
        cdpt->start(timeout);
        sendWnd[cdpt->SID] = cdpt;
        hbt.stop();
    } else
        delete cdpt;
}

void CCPS::NA_ACK(unsigned short AID, const QByteArray &data) {
    auto *tmp = new CDPT(this);
    tmp->AID = AID;
    tmp->cf = 0x22;
    if (!data.isEmpty()) {
        tmp->cf |= 0x40;
        tmp->data = data;
    }
    transmitShunt_(tmp);
    updateWnd_();
}

void CCPS::updateWnd_() {
    while (sendWnd.contains(ID)) {
        if (!sendWnd[ID]->isActive()) {
            delete sendWnd[ID];
            sendWnd.remove(ID);
            ID++;
        } else
            break;
    }
    if ((sendWnd.size() < 256) && (!sendBuf.isEmpty())) {
        sendPackage_(sendBuf.front());
        sendBuf.pop_front();
    }
    if (sendWnd.isEmpty() && (!hbt.isActive()))
        hbt.start(hbtTime);
    //接收窗口连续性判断
    bool isRead = false;
    while (recvWnd.contains(OID + 1)) {
        if ((((recvWnd[OID + 1].cf) >> 7) & 0x01)) {//如果是链表包,转为链表状态
            if (!link) {
                link = true;
                linkStart = OID + 1;
            }
        } else {
            if (link) {
                //合并包并触发readyRead
                QByteArray dataFull;
                unsigned short j = linkStart;
                while (j != OID + 2) {
                    dataFull.append(recvWnd[j].data, recvWnd[j].data.size());
                    recvWnd.remove(j);
                    j++;
                }
                readBuf.append(dataFull);
                link = false;
            } else {
                readBuf.append(recvWnd[OID + 1].data);
                recvWnd.remove(OID + 1);
            }
            isRead = true;
        }
        OID++;
    }
    if (isRead) emit readyRead();
}

void CCPS::setTimeout(unsigned short num) {
    timeout = num;
}

void CCPS::setRetryNum(unsigned char num) {
    retryNum = num;
}

void CCPS::transmitShunt_(CDPT *cdpt) {
    auto NA = ((cdpt->cf >> 5) & 0x01) == 1;
    if (NA) sendPackage_(cdpt);
    else sendBuf.append(cdpt);
}

CDPT::~CDPT() = default;

CDPT::CDPT(QObject *parent) : QTimer(parent) {}
