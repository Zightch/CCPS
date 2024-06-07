#include "CFUPS.h"
#include "CFUPSManager.h"
#include <QDateTime>
#include <QThread>
#include "tools/tools.h"
#include "key.h"
#include "CFUPS_macro.h"

#define THREAD_CHECK(ret) if (!threadCheck_(__FUNCTION__))return ret

CFUPS::CFUPS(CFUPSManager *parent, const QHostAddress &IP, unsigned short p) : QObject(parent), IP(IP), port(p), cm(parent) {
    int time = (retryNum + 1) * timeout;
    if (time > 30000)time = 30000;
    sexticTiming.setInterval(time);
    connect(&hbt, &QTimer::timeout, this, [&]() {
        auto *cdpt = newCDPT_();
        cdpt->cf = 0x05;
        cdpt->SID = ID + sendWnd.size() + sendBufLv1.size();
        sendBufLv1.append(cdpt);
        updateWnd_();
    });
    connect(&sexticTiming, &QTimer::timeout, this, [&] {
        close("6次握手超时, 连接关闭");
    });
}

bool CFUPS::threadCheck_(const QString &funcName) {
    if (QThread::currentThread() == thread())return true;
    qWarning()
            << "函数" << funcName << "不允许在其他线程调用, 操作被拒绝.\n"
            << "对象:" << this << ", 调用线程:" << QThread::currentThread() << ", 对象所在线程:" << thread();
    return false;
}

QHostAddress CFUPS::getIP() {
    THREAD_CHECK(QHostAddress::Null);
    return IP;
}

unsigned short CFUPS::getPort() {
    THREAD_CHECK(0);
    return port;
}

void CFUPS::proc_(QByteArray data) { // 该函数只能被CFUPSManager调用
    if (sharedKey.size() == LEN_25519 && IV.size() == IV_LEN) { // 如果共享密钥与IV准备好了
        QByteArray cipher = data;
        data.clear();
        data.resize(cipher.size() - IV_LEN);
        if (DecryptData((CUCP) cipher.data(), (int) cipher.size(), (CUCP) sharedKey.data(), (CUCP) IV.data(), (UCP) data.data()) <= 0)
            return;
    }

    data = data.mid(HEAD_RAND_LEN); // 撇去32个随机数
    unsigned char cf = data[0];

    bool UDL = ((cf >> 7) & 0x01);
    bool UD = ((cf >> 6) & 0x01);
    bool NA = ((cf >> 5) & 0x01);
    bool RT = ((cf >> 4) & 0x01);
    auto cmd = (unsigned char) (cf & (unsigned char) 0x07);

    if (NA && RT)return;
    if (1 <= cmd && cmd <= 5 && !UDL) {
        if (cmd == 1)cmdRC_(data); // RC指令, 请求
        if (cmd == 2)cmdACK_(NA, UD, data); // ACK指令, 应答
        if (cmd == 3)cmdRC_ACK_(RT, UD, data);
        if (cmd == 4)cmdC_(NA, UD, data); // C指令, 断开
        if (cmd == 5)cmdH_(RT, data); // 心跳
    } else {
        if (!NA) {//需要回复
            unsigned short SID = (*(unsigned short *) (data.data() + 1));
            if (!initiative && cs == 1 && ID == 2 && OID == 1 && SID == 2 && data.mid(3).size() == IV_LEN && UD && !UDL) {
                IV = data.mid(3);
                OID++;
                NA_ACK_(SID);
            } else {
                NA_ACK_(SID);
                if (UD) { // 有用户数据
                    if (recvWnd.contains(SID) && !RT)close("窗口数据发生重叠"); // 如果窗口包含该数据而且不是重发包
                    else if (!RT || !recvWnd.contains(SID)) { //如果是重发包，并且接收窗口中已经有该数据，则不需要再次存储
                        // 从数据包中提取用户数据，跳过前三个字节的头部信息
                        recvWnd[SID] = {cf, SID, data.mid(3)};
                    }
                }
            }
        } else if (UD && cs == 2) {//有用户数据
            readBuf.append(data.mid(1));
            emit readyRead();
        }
    }
    updateWnd_();

    if (cs == 1 && ID == 2 && OID == 1 && readBuf.size() == 1) { // 完成密钥交换
        sharedKey.clear();
        sharedKey.resize(LEN_25519);
        if (GenSharedKey((CUCP) localKey.data(), (CUCP) readBuf[0].data(), (UCP) sharedKey.data()) <= 0) {
            sharedKey.clear();
            IV.clear();
            cs = 3;
            close("共享密钥生成失败");
            return;
        }
        readBuf.pop_front();
        if (initiative) { // 主动生成IV并发送
            QByteArray newIV;
            newIV.resize(IV_LEN);
            Rand((UCP) newIV.data(), IV_LEN);
            sendBufLv2.append(newIV);
            updateWnd_();
            IV = newIV;
        }
    }
    if ((initiative && cs == 1 && ID == 3 && OID == 1) || (!initiative && cs == 1 && ID == 2 && OID == 2)) {
        // 对方已接受IV或者我已接受IV
        // 连接成功
        cs = 2;
        sexticTiming.stop();
        cm->cfupsConnected_(this);
        hbt.start(hbtTime);
    }
}

void CFUPS::send(const QByteArray &data) {
    THREAD_CHECK();
    if (cs != 2 || data.isEmpty())return;
    sendBufLv2.append(data);
    updateWnd_();
}

void CFUPS::sendNow(const QByteArray &data) {
    THREAD_CHECK();
    if (cs != 2 || data.isEmpty())return;
    auto *tmp = new CDPT(this);
    tmp->data = data;
    tmp->cf = 0x60;
    sendPackage_(tmp);
    delete tmp;
}

void CFUPS::connectToHost_() { // 该函数只能被CFUPSManager调用
    if (cs != -1)return;
    initiative = true;
    IV.resize(IV_LEN);
    Rand((UCP) IV.data(), IV_LEN); // 生成IV数组
    if (!tryGenKeyPair_()) { // 生成密钥对
        close("密钥对生成失败");
        return;
    }
    auto cdpt = newCDPT_();
    cdpt->SID = 0;
    cdpt->cf = 0x41;
    cdpt->data = IV + localCrt;
    sendBufLv1.append(cdpt); // 直接放入一级缓存
    cs = 0; // 半连接
    updateWnd_();
}

void CFUPS::close(const QByteArray &data) {
    THREAD_CHECK();
    if (cs != 3) {
        auto cdpt = new CDPT(this);
        cdpt->cf = 0x24;
        if (!data.isEmpty()) {
            cdpt->cf |= 0x40;
            cdpt->data = data;
        }
        sendPackage_(cdpt);
        delete cdpt;
        cs = 3;
    }
    for (auto i: sendWnd)i->deleteLater();
    for (auto i: sendBufLv1)i->deleteLater();
    sendWnd.clear();
    sendBufLv1.clear();
    sendBufLv2.clear();
    hbt.stop();
    sexticTiming.stop();
    emit disconnected(data);
}

void CFUPS::updateWnd_() {
    // 更新发送窗口
    while (sendWnd.contains(ID)) { // 释放掉已经接收停止的数据包
        if (sendWnd[ID]->isActive())break; // 如果数据包还未被接收, break
        delete sendWnd[ID]; // 释放内存
        sendWnd.remove(ID); // 移除
        ID++; // ID++
    }
    updateSendBuf_(); // 更新发送缓存
    while ((sendWnd.size() < wndSize) && (!sendBufLv1.isEmpty())) { // 循环添加一级缓存的数据包
        auto cdpt = sendBufLv1.front(); // 取首元素
        sendBufLv1.pop_front();
        sendWnd[cdpt->SID] = cdpt; // 放到发送窗口
        sendPackage_(cdpt); // 发送数据包
        cdpt->start(timeout); // 启动定时器
    }
    while (recvWnd.contains(OID + 1)) { // 如果接收到了数据
        OID++; // OID++
        recvBuf.append(recvWnd[OID].data); // 先添加进来数据
        if (!((recvWnd[OID].cf >> 7) & 0x01)) { // 如果不是链表包
            readBuf.append(recvBuf); // 添加到可读缓存
            recvBuf.clear(); // 清空接收缓存
        }
        recvWnd.remove(OID); // 移除当前数据包
    }
    if (!readBuf.isEmpty() && cs == 2)emit readyRead();
}

void CFUPS::sendPackage_(CDPT *cdpt) { // 只负责构造数据包和发送
    QByteArray data;
    data.append((char) cdpt->cf);
    unsigned char cmd = (char) (cdpt->cf & (char) 0x07);
    bool NA = (cdpt->cf >> 5) & 0x01;
    if (!NA)data += dump(cdpt->SID);
    if ((cmd == 2) || (cmd == 3))data += dump(cdpt->AID);
    if ((cdpt->cf >> 6) & 0x01)data += cdpt->data;
    QByteArray rand;
    rand.resize(HEAD_RAND_LEN);
    Rand((UCP) rand.data(), HEAD_RAND_LEN);
    data = rand + data;
    if (sharedKey.size() == LEN_25519 && IV.size() == IV_LEN && !cdpt->isNotEncrypt) {
        QByteArray cipher;
        cipher.resize(data.size() + IV_LEN);
        if (EncryptData((CUCP) data.data(), (int) data.size(), (CUCP) sharedKey.data(), (CUCP) IV.data(), (UCP) cipher.data()) <= 0) {
            cs = 3;
            sharedKey.clear();
            IV.clear();
            close("数据加密错误");
            return;
        }
        data = cipher;
    }
    cm->send_(IP, port, data);
}

void CFUPS::updateSendBuf_() { // 更新发送缓存
    // 从二级缓存解包到一级缓存
    if (!sendBufLv1.isEmpty() || sendBufLv2.isEmpty())return;
    auto data = sendBufLv2.front(); // 拿一个数据
    sendBufLv2.pop_front();
    // 全部序列化到一级缓存
    if (data.size() <= dataBlockSize || cs != 2) { // 数据包长度小于块大小, 或者属于握手数据包
        auto cdpt = newCDPT_();
        cdpt->data = data;
        cdpt->cf = 0x40;
        cdpt->SID = ID + sendWnd.size();
        sendBufLv1.append(cdpt);
    } else { // 否则进行拆包
        QByteArrayList dataBlock; // 数据块
        QByteArray i = data, tmp;
        while (!i.isEmpty()) { // 迭代
            unsigned short dbs = dataBlockSize;
            if (i.size() <= dataBlockSize)dbs = i.size(); // 计算实际数据块大小
            tmp.append(i, dbs); // 赋值tmp
            dataBlock.append(tmp); // 添加到数据块
            tmp.clear(); // 清空tmp
            i = i.mid(dbs); // 迭代
        }
        auto baseID = sendWnd.size(); // 获取当前窗口长度
        for (qsizetype j = 0; j < dataBlock.size(); j++) {
            auto cdpt = newCDPT_();
            cdpt->data = dataBlock[j];
            cdpt->SID = ID + j + baseID;
            if (j != dataBlock.size() - 1)cdpt->cf = 0xC0; // 链表包
            else cdpt->cf = 0x40; // 非链表包
            sendBufLv1.append(cdpt);
        }
    }
}

CDPT *CFUPS::newCDPT_() {
    auto *cdpt = new CDPT(this);
    connect(cdpt, &CDPT::timeout, this, &CFUPS::sendTimeout_);
    return cdpt;
}

void CFUPS::sendTimeout_() { // 只做重发包逻辑和重试次数过多逻辑
    auto cdpt = (CDPT *) sender();
    if (cdpt->retryNum < retryNum) {
        cdpt->retryNum++;
        cdpt->cf |= 0x10;
        sendPackage_(cdpt);
    } else close("对方应答超时");
}

QByteArray CFUPS::nextPendingData() {
    THREAD_CHECK({});
    auto tmp = readBuf.front();
    readBuf.pop_front();
    return tmp;
}

bool CFUPS::hasData() {
    THREAD_CHECK(false);
    return !readBuf.isEmpty();
}

QByteArrayList CFUPS::readAll() {
    THREAD_CHECK({});
    auto tmp = readBuf;
    readBuf.clear();
    return tmp;
}

void CFUPS::NA_ACK_(unsigned short AID, const QByteArray &data) {
    auto cdpt = new CDPT(this);
    cdpt->AID = AID;
    cdpt->cf = 0x22;
    if (!data.isEmpty()) {
        cdpt->cf |= 0x40;
        cdpt->data = data;
    }
    sendPackage_(cdpt);
    delete cdpt;
}

CFUPS::~CFUPS() = default;

CDPT::CDPT(QObject *parent) : QTimer(parent) {}

CDPT::~CDPT() = default;
