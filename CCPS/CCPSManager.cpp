#include "CCPSManager.h"
#include "tools/tools.h"
#include "CCPS.h"
#include <QDateTime>
#include <QUdpSocket>
#include <QNetworkDatagram>
#include <QThread>

#define THREAD_CHECK(ret) if (!threadCheck_(__FUNCTION__))return ret

void CCPSManager::proc_(const QHostAddress &IP, unsigned short port, const QByteArray &data) { // 来源于recv_调用, 不会被别的线程调用, 是私有函数
    auto ipPort = IPPort(IP, port); // 转字符串
    if (ipPort.isEmpty())return; // 转换失败
    if (ccps.contains(ipPort) || connecting.contains(ipPort)) { // 如果已经存在对象
        if (ccps.contains(ipPort))ccps[ipPort]->proc_(data);
        if (connecting.contains(ipPort))connecting[ipPort]->proc_(data);
        return;
    }
    const char *dataC = data.data();
    char cf = dataC[0];
    if ((cf & 0x07) != 0x01)return; // 如果不是连接请求, 直接丢弃
    if (data.size() < 3)return; // 数据包不完整
    unsigned short SID = (*(unsigned short *) (dataC + 1)); // 提取SID
    if (((cf >> 5) & 0x01) || SID != 0)return; // NA位不能为1, SID必须是0
    if (ccps.size() >= connectNum)return; // 连接上限
    auto tmp = new CCPS(this, IP, port);
    connecting[ipPort] = tmp;
    connect(tmp, &CCPS::disconnected, this, &CCPSManager::requestInvalid_);
    tmp->proc_(data);
}

CCPSManager::CCPSManager(QObject *parent) : QObject(parent) {}

CCPSManager::~CCPSManager() = default; // 不允许被外部调用

void CCPSManager::deleteLater() {QObject::deleteLater();} // 不允许被外部调用

void CCPSManager::close() { // 这个只是关闭管理器
    THREAD_CHECK();
    auto rm = [this](QHash<QString, CCPS *> &cs) {
        for (auto i: cs) {
            disconnect(i, &CCPS::disconnected, this, &CCPSManager::requestInvalid_);
            disconnect(i, &CCPS::disconnected, this, &CCPSManager::rmCCPS_);
            i->close("管理器服务关闭");
            if (i->cs < 1)i->deleteLater(); // 如果i还处于未连接状态, 自己delete
        }
        cs.clear();
    };
    rm(ccps);
    rm(connecting);
    if (ipv4 != nullptr)ipv4->deleteLater();
    if (ipv6 != nullptr)ipv6->deleteLater();
    ipv4 = nullptr;
    ipv6 = nullptr;
}

void CCPSManager::quit() { // delete对象调用它
    THREAD_CHECK();
    close();
    deleteLater();
}

QString CCPSManager::bind(const QString &ipStr, unsigned short port) {
    THREAD_CHECK({}); // 不允许被别的线程调用
    if (isBind() != 0 && !isBindAll)return "CCPS管理器已绑定";
    QHostAddress ip(ipStr); // 构造QHostAddress对象
    QUdpSocket **udpTmp = nullptr; // 使用哪个udp, 双重指针
    auto protocol = ip.protocol(); // 获取ip的协议
    if (protocol == QUdpSocket::IPv4Protocol)udpTmp = &ipv4; // 如果是ipv4, 获取ipv4的udp指针
    else if (protocol == QUdpSocket::IPv6Protocol)udpTmp = &ipv6; // 如果是ipv6, 获取ipv6的udp指针
    if (udpTmp == nullptr) return "IP不正确"; // 如果udpTmp为空, 说明IP不正确
    auto &udp = (*udpTmp); // 获取udpTmp指向的指针对象
    QString error; // 错误信息
    if (udp == nullptr) { // 如果udp是空
        udp = new QUdpSocket(this); // new对象
        if (udp->bind(ip, port)) // 绑定
            connect(udp, &QUdpSocket::readyRead, this, &CCPSManager::recv_);
        else { // 绑定失败
            error = udp->errorString();
            delete udp;
            udp = nullptr;
        }
    } else error = "CCPS管理器已绑定"; // 否则CCPS已绑定
    return error;
}

QStringList CCPSManager::bind(unsigned short port) { // 同时绑定ipv4和ipv6
    THREAD_CHECK({}); // 不允许被别的线程调用
    isBindAll = true;
    QStringList tmp;
    auto tmp4 = bind("0.0.0.0", port);
    if (!tmp4.isEmpty())tmp.append("IPv4: " + tmp4);
    auto tmp6 = bind("::", port);
    if (!tmp6.isEmpty())tmp.append("IPv6: " + tmp6);
    isBindAll = false;
    return tmp;
}

void CCPSManager::connectToHost(const QString &ipStr, unsigned short port) {
    THREAD_CHECK();
    connectToHost(QHostAddress(ipStr), port);
}

void CCPSManager::connectToHost(const QHostAddress &ip, unsigned short port) {
    THREAD_CHECK(); // 检查线程
    QUdpSocket *udp = nullptr;
    auto protocol = ip.protocol();
    if (protocol == QUdpSocket::IPv4Protocol)udp = ipv4;
    else if (protocol == QUdpSocket::IPv6Protocol)udp = ipv6;
    if (udp == nullptr) { // IP协议检查失败
        emit connectFail(ip, port, "以目标IP协议所管理的CCPS管理器未绑定");
        return;
    }
    if ((ccps.size() >= connectNum)) {
        emit connectFail(ip, port, "当前管理器连接的CCPS数量已达到上限");
        return;
    }
    auto ipPort = IPPort(ip, port);
    if (ccps.contains(ipPort)) {
        emit connected(ccps[ipPort]);
        return;
    }
    if (!connecting.contains(ipPort)) {
        auto tmp = new CCPS(this, ip, port);
        connecting[ipPort] = tmp;
        connect(tmp, &CCPS::disconnected, this, &CCPSManager::requestInvalid_);
        tmp->connectToHost_();
    }
}

void CCPSManager::recv_() { // 来源于udpSocket信号调用, 不会被别的线程调用, 是私有函数
    auto udp = (QUdpSocket *) sender();
    while (udp->hasPendingDatagrams()) {
        auto datagrams = udp->receiveDatagram();
        auto IP = datagrams.senderAddress();
        auto port = datagrams.senderPort();
        auto data = datagrams.data();
        if (!data.isEmpty()) {
            proc_(IP, port, data);
            emit cLog("↓ " + IPPort(IP, port) + " : " + bytesToHexString(data));
        }
    }
}

void CCPSManager::setMaxConnectNum(int num) {
    THREAD_CHECK(); // 不允许被别的线程调用
    if (num > 0)connectNum = num;
}

int CCPSManager::getMaxConnectNum() {
    THREAD_CHECK(-1); // 不允许被别的线程调用
    return connectNum;
}

int CCPSManager::getConnectedNum() {
    THREAD_CHECK(-1); // 不允许被别的线程调用
    return (int) ccps.size();
}

int CCPSManager::isBind() { // 已经绑定, 1表示只绑定了IPv4, 2表示只绑定了IPv6, 3表示IPv4和IPv6都绑定了
    THREAD_CHECK(-1); // 不允许被别的线程调用
    int tmp = 0;
    if (ipv4 != nullptr)tmp |= 1;
    if (ipv6 != nullptr)tmp |= 2;
    return tmp;
}

void CCPSManager::send_(const QHostAddress &IP, unsigned short port, const QByteArray &data) {
    QUdpSocket *udp = nullptr;
    auto protocol = IP.protocol();
    if (protocol == QUdpSocket::IPv4Protocol)udp = ipv4;
    else if (protocol == QUdpSocket::IPv6Protocol)udp = ipv6;
    if (udp == nullptr)return;
    udp->writeDatagram(data, IP, port);
    emit cLog("↑ " + IPPort(IP, port) + " : " + bytesToHexString(data));
}

bool CCPSManager::threadCheck_(const QString &funcName) {
    if (QThread::currentThread() == thread())return true;
    qWarning()
            << "函数" << funcName << "不允许在其他线程调用, 操作被拒绝.\n"
            << "对象:" << this << ", 调用线程:" << QThread::currentThread() << ", 对象所在线程:" << thread();
    return false;
}

void CCPSManager::ccpsConnected_(CCPS *c) { // 当CCPS处理后连接成功调用这个函数
    auto key = IPPort(c->IP, c->port);
    connecting.remove(key);
    if (ccps.size() < connectNum) {
        disconnect(c, &CCPS::disconnected, this, &CCPSManager::requestInvalid_); // 断开连接
        connect(c, &CCPS::disconnected, this, &CCPSManager::rmCCPS_);
        ccps[key] = c;
        emit connected(c);
    } else {
        c->close("当前连接的CCPS数量已达到上限");
        c->deleteLater();
        if (c->initiative)emit connectFail(c->IP, c->port, "当前连接的CCPS数量已达到上限");
    }
}

void CCPSManager::requestInvalid_(const QByteArray &data) {
    auto c = (CCPS *) sender();
    c->deleteLater();
    connecting.remove(IPPort(c->IP, c->port));
    if (c->initiative)emit connectFail(c->IP, c->port, data); // 如果是主动连接的触发连接失败
}

void CCPSManager::rmCCPS_() {
    auto c = (CCPS *) sender();
    ccps.remove(IPPort(c->IP, c->port));
}
