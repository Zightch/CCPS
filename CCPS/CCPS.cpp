#include "CCPS.h"
#include "CCPSManager.h"
#include <QDateTime>
#include <QThread>
#include "tools/tools.h"

#define THREAD_CHECK(ret) if (!threadCheck_(__FUNCTION__))return ret

CCPS::CCPS(CCPSManager *parent, const QHostAddress &IP, unsigned short p) : QObject(parent), IP(IP), port(p), cm(parent) {
    connect(&hbt, &QTimer::timeout, this, [&]() {
        if (cs == 1) {
            auto *cdpt = newCDPT();
            cdpt->cf = 0x05;
            cdpt->SID = ID + sendWnd.size() + sendBufLv1.size();
            sendBufLv1.append(cdpt);
            updateWnd_();
        }
    });
}

bool CCPS::threadCheck_(const QString &funcName) {
    if (QThread::currentThread() == thread())return true;
    qWarning()
            << "函数" << funcName << "不允许在其他线程调用, 操作被拒绝.\n"
            << "对象:" << this << ", 调用线程:" << QThread::currentThread() << ", 对象所在线程:" << thread();
    return false;
}

QHostAddress CCPS::getIP() {
    THREAD_CHECK(QHostAddress::Null);
    return IP;
}

unsigned short CCPS::getPort() {
    THREAD_CHECK(0);
    return port;
}

void CCPS::proc_(const QByteArray &data) { // 该函数只能被CCPSManager调用
    const char *data_c = data.data();
    unsigned char cf = data_c[0];

    bool UDL = ((cf >> 7) & 0x01);
    bool UD = ((cf >> 6) & 0x01);
    bool NA = ((cf >> 5) & 0x01);
    bool RT = ((cf >> 4) & 0x01);
    auto cmd = (unsigned char) (cf & (unsigned char) 0x07);

    if (NA && RT)return;
    if (1 <= cmd && cmd <= 5 && !UDL) {
        if (cmd == 1) { // RC指令, 请求
            if (!RT) {
                auto cdpt = newCDPT();
                cdpt->SID = 0;
                cdpt->AID = 0;
                cdpt->cf = (char) 0x03;
                sendBufLv1.append(cdpt);
                if (cs == -1) {
                    OID = 0;
                    cs = 0;//半连接
                }
            }
        } else if (cmd == 2) { // ACK指令, 应答
            if (NA) {
                unsigned short AID = (*(unsigned short *) (data_c + 1));
                if (sendWnd.contains(AID)) {
                    sendWnd[AID]->stop();
                    if (AID == 0 && cs == 0) {
                        cs = 1;
                        cm->ccpsConnected_(this);
                        hbt.start(hbtTime);
                    }
                }
            }
        } else if (cmd == 3) { // RC ACK指令, 请求应答
            if (ID == 0 && OID == 65535 && !RT) {
                NA_ACK(0);
                unsigned short SID = (*(unsigned short *) (data_c + 1));
                unsigned short AID = (*(unsigned short *) (data_c + 3));
                if (cs == 0 && SID == 0 && AID == 0) {
                    ID = 1;
                    OID = 0;
                    cs = 1;
                    delete sendWnd[0];
                    sendWnd.remove(0);
                    cm->ccpsConnected_(this);
                    hbt.start(hbtTime);
                }
            } else if (RT)NA_ACK(0);
        } else if (cmd == 4) { // C指令, 断开
            if (NA) { // NA必须有
                QByteArray userData;
                if (UD)userData = data.mid(1);
                close(userData);
            }
        } else if (cmd == 5) { // H命令, 心跳
            if (cs == 1) {
                unsigned short SID = (*(unsigned short *) (data_c + 1));
                NA_ACK(SID);
                if (SID == OID + 1) {
                    OID = SID;
                    hbt.stop();
                    hbt.start(hbtTime);
                }
            }
        }
    } else {
        if (!NA) {//需要回复
            unsigned short SID = (*(unsigned short *) (data_c + 1));
            NA_ACK(SID);
            if (UD) { // 有用户数据
                if (recvWnd.contains(SID) && !RT)close("窗口数据发生重叠"); // 如果窗口包含该数据而且不是重发包
                else if (!RT || !recvWnd.contains(SID)) { //如果是重发包，并且接收窗口中已经有该数据，则不需要再次存储
                    // 从数据包中提取用户数据，跳过前三个字节的头部信息
                    recvWnd[SID] = {cf, SID, data.mid(3)};
                }
            }
        } else if (UD) {//有用户数据
            readBuf.append(data.mid(1));
            emit readyRead();
        }
    }
    updateWnd_();
}

void CCPS::send(const QByteArray &data) {
    THREAD_CHECK();
    if (cs != 1 || data.isEmpty())return;
    sendBufLv2.append(data);
    updateWnd_();
}

void CCPS::sendNow(const QByteArray &data) {
    THREAD_CHECK();
    if (cs != 1 || data.isEmpty())return;
    auto *tmp = new CDPT(this);
    tmp->data = data;
    tmp->cf = 0x60;
    sendPackage_(tmp);
    delete tmp;
}

void CCPS::connectToHost_() { // 该函数只能被CCPSManager调用
    if (cs != -1)return;
    initiative = true;
    auto cdpt = newCDPT();
    cdpt->SID = 0;
    cdpt->cf = (char) 0x01;
    sendBufLv1.append(cdpt); // 直接放入一级缓存
    cs = 0; // 半连接
    updateWnd_();
}

void CCPS::close(const QByteArray &data) {
    THREAD_CHECK();
    if (cs != 2) {
        auto cdpt = new CDPT(this);
        cdpt->cf = 0x24;
        if (!data.isEmpty()) {
            cdpt->cf |= 0x40;
            cdpt->data = data;
        }
        sendPackage_(cdpt);
        delete cdpt;
        cs = 2;
    }
    for (auto i: sendWnd)i->deleteLater();
    for (auto i: sendBufLv1)i->deleteLater();
    sendWnd.clear();
    sendBufLv1.clear();
    sendBufLv2.clear();
    emit disconnected(data);
}

void CCPS::updateWnd_() {
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
    if (!readBuf.isEmpty())emit readyRead();
}

void CCPS::sendPackage_(CDPT *cdpt) { // 只负责构造数据包和发送
    QByteArray data;
    data.append((char) cdpt->cf);
    unsigned char cmd = (char) (cdpt->cf & (char) 0x07);
    bool NA = (cdpt->cf >> 5) & 0x01;
    if (!NA)data += dump(cdpt->SID);
    if ((cmd == 2) || (cmd == 3))data += dump(cdpt->AID);
    if ((cdpt->cf >> 6) & 0x01)data += cdpt->data;
    cm->send_(IP, port, data);
}

void CCPS::updateSendBuf_() { // 更新发送缓存
    // 从二级缓存解包到一级缓存
    if (!sendBufLv1.isEmpty() || sendBufLv2.isEmpty())return;
    auto data = sendBufLv2.front(); // 拿一个数据
    sendBufLv2.pop_front();
    // 全部序列化到一级缓存
    if (data.size() <= dataBlockSize) { // 数据包长度小于块大小
        auto cdpt = newCDPT();
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
            auto cdpt = newCDPT();
            cdpt->data = dataBlock[j];
            cdpt->SID = ID + j + baseID;
            if (j != dataBlock.size() - 1)cdpt->cf = 0xC0; // 链表包
            else cdpt->cf = 0x40; // 非链表包
            sendBufLv1.append(cdpt);
        }
    }
}

CDPT *CCPS::newCDPT() {
    auto *cdpt = new CDPT(this);
    connect(cdpt, &CDPT::timeout, this, &CCPS::sendTimeout_);
    return cdpt;
}

void CCPS::sendTimeout_() { // 只做重发包逻辑和重试次数过多逻辑
    auto cdpt = (CDPT *) sender();
    if (cdpt->retryNum < retryNum) {
        cdpt->retryNum++;
        cdpt->cf |= 0x10;
        sendPackage_(cdpt);
    } else close("对方应答超时");
}

QByteArray CCPS::nextPendingData() {
    THREAD_CHECK({});
    auto tmp = readBuf.front();
    readBuf.pop_front();
    return tmp;
}

bool CCPS::hasData() {
    THREAD_CHECK(false);
    return !readBuf.isEmpty();
}

QByteArrayList CCPS::readAll() {
    THREAD_CHECK({});
    auto tmp = readBuf;
    readBuf.clear();
    return tmp;
}

void CCPS::NA_ACK(unsigned short AID) {
    auto cdpt = new CDPT(this);
    cdpt->AID = AID;
    cdpt->cf = (char) 0x22;
    sendPackage_(cdpt);
    delete cdpt;
}

CCPS::~CCPS() = default;

CDPT::CDPT(QObject *parent) : QTimer(parent) {}

CDPT::~CDPT() = default;
