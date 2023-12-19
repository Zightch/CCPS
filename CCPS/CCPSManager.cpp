#include "CCPSManager.h"
#include "tools/Dump.h"
#include "tools/IP.h"
#include "tools/Key.h"
#include "CCPS.h"
#include <openssl/sha.h>
#include <QDateTime>
#include <QNetworkDatagram>

CCPSManager::CCPSManager(QObject *parent) : QObject(parent) {
    connect(this, &CCPSManager::sendS_, this, &CCPSManager::sendF_, Qt::QueuedConnection);
}

void CCPSManager::proc_(const QHostAddress &IP, unsigned short port, const QByteArray &data) {
    auto ef = [&](const QByteArray &data) {
        Dump error;
        error.push((char) 0x64);
        error.push(data.data(), data.size());
        QByteArray tmp;
        tmp.append(error.get(), (qsizetype) error.size());
        emit sendS_(IP, port, tmp);
    };
    auto ipPort = IPPort(IP, port);
    if (ipPort.isEmpty()) {
        ef("IP协议不匹配");
        emit requestInvalid(IP, port);
        return;
    }
    if (ccps.exist(ipPort)) {
        emit ccps[ipPort]->procS_(data);
        return;
    }
    if (connecting.exist(ipPort)) {
        emit connecting[ipPort]->procS_(data);
        return;
    }

    const char *dataC = data.data();
    const auto dataSize = data.size();

    //检查数据是否被篡改
    {
        //检查校验和
        auto c0 = *(unsigned long long *) dataC;
        QByteArray b;
        b.append(dataC + 8, dataSize - 8);
        if (c0 != checksum0(b))//如果无符号校验和不匹配
            return;
        auto c1 = *(int *) (dataC + 8);
        b.clear();
        b.append(dataC + 12, dataSize - 12);
        if (c1 != checksum1(b))//如果有符号校验和不匹配
            return;

        //检查SHA-256
        b.clear();
        b.append(dataC + 44, dataSize - 44);
        unsigned long long s256t[4] = {0};//自己计算的SHA-256
        auto s256p = (unsigned long long *) (dataC + 12);//对方给的-SHA256
        SHA256((unsigned char *) b.data(), b.size(), (unsigned char *) s256t);
        if (s256t[0] != s256p[0] || s256t[1] != s256p[1] || s256t[2] != s256p[2] || s256t[3] != s256p[3])
            return;
    }
    //检查通过

    char cf = dataC[44];
    if ((cf & 0x07) != 0x01)//如果不是连接请求
        return;
    if (data.size() < 47) {
        ef("数据包不完整");
        emit requestInvalid(IP, port);
        return;
    }
    unsigned short SID = (*(unsigned short *) (dataC + 45));
    if (!((!((cf >> 5) & 0x01)) && (SID == 0))) {
        ef("数据内容不符合规范");
        emit requestInvalid(IP, port);
        return;
    }
    if (ccps.size() >= connectNum) {
        ef("当前管理器连接的CCPS数量已达到上限");
        emit requestInvalid(IP, port);
        return;
    }
    auto tmp = new CCPS(this, IP, port);
    connecting[ipPort] = tmp;
    connect(tmp, &CCPS::connected_, this, &CCPSManager::connected_, Qt::QueuedConnection);
    connect(tmp, &CCPS::disconnected, this, &CCPSManager::requestInvalid_, Qt::QueuedConnection);
    emit tmp->procS_(data);
}

CCPSManager::~CCPSManager() {
    close();
}

QByteArrayList CCPSManager::bind(unsigned short port) {
    QByteArrayList tmp;
    auto tmp4 = bind("0.0.0.0", port);
    if (!tmp4.isEmpty())
        tmp.append("IPv4: " + tmp4);
    auto tmp6 = bind("::", port);
    if (!tmp6.isEmpty())
        tmp.append("IPv6: " + tmp6);
    return tmp;
}

QByteArray CCPSManager::bind(const QByteArray &IP, unsigned short port) {
    QHostAddress ip(IP);
    QUdpSocket **udpTmp;
    char ipProtocol = 0;
    switch (ip.protocol()) {
        case QAbstractSocket::IPv4Protocol:
            udpTmp = &ipv4;
            ipProtocol = 1;
            break;
        case QAbstractSocket::IPv6Protocol:
            udpTmp = &ipv6;
            ipProtocol = 2;
            break;
        default:
            break;
    }
    if (ipProtocol == 0) return "IP不正确";
    auto &udp = (*udpTmp);
    if (udp == nullptr) {
        udp = new QUdpSocket(this);
        if (udp->bind(ip, port)) {
            udpErrorInfo = "";
            connect(udp, &QUdpSocket::readyRead, this, &CCPSManager::recv_);
        } else {
            udpErrorInfo = udp->errorString().toLocal8Bit();
            delete udp;
            udp = nullptr;
        }
    } else
        udpErrorInfo = "CCPS管理器已绑定";
    return udpErrorInfo;
}

void CCPSManager::setMaxConnectNum(unsigned long long cn) {
    connectNum = cn;
}

unsigned long long CCPSManager::getConnectNum() {
    return ccps.size();
}

void CCPSManager::sendF_(const QHostAddress& IP, unsigned short port, const QByteArray& data) {
    switch (IP.protocol()) {
        case QAbstractSocket::IPv4Protocol:
            if (ipv4 != nullptr)ipv4->writeDatagram(data, IP, port);
            break;
        case QAbstractSocket::IPv6Protocol:
            if (ipv6 != nullptr)ipv6->writeDatagram(data, IP, port);
            break;
        default:
            break;
    }
}

void CCPSManager::connectFail_(const QByteArray& data) {
    CCPS *c = (CCPS *) sender();
    QHostAddress IP = c->IP;
    unsigned short port = c->port;
    connecting.remove(IPPort(IP, port));
    delete c;
    emit connectFail(IP, port, data);
}

void CCPSManager::connected_() {
    CCPS *c = (CCPS *) sender();
    QByteArray key = IPPort(c->IP, c->port);
    connecting.remove(key);
    if (ccps.size() < connectNum) {
        disconnect(c, &CCPS::disconnected, nullptr, nullptr);
        connect(c, &CCPS::disconnected, this, &CCPSManager::rmCCPS_);
        ccps[key] = c;
        emit connected(c);
    } else {
        c->close("当前连接的CCPS数量已达到上限");
        if (c->initiative) {//根据主动性触发不同的失败信号到外层
            emit connectFail(c->IP, c->port, "当前连接的CCPS数量已达到上限");
        } else {
            emit requestInvalid(c->IP, c->port);
        }
    }
}

void CCPSManager::close() {
    auto callBack = [this](CCPS *&i, const char *) {
        disconnect(i, &CCPS::disconnected, this, &CCPSManager::rmCCPS_);
        disconnect(i, &CCPS::disconnected, this, &CCPSManager::connectFail_);
        disconnect(i, &CCPS::disconnected, this, &CCPSManager::requestInvalid_);
        i->close("管理器服务关闭");
        delete i;
        i = nullptr;
    };
    connecting.traverse(callBack);
    connecting.clear();
    ccps.traverse(callBack);
    ccps.clear();
    delete ipv4;
    ipv4 = nullptr;
    delete ipv6;
    ipv6 = nullptr;
}

int CCPSManager::isBind() {
    int tmp = 0;
    if (ipv4 != nullptr)
        tmp++;
    if (ipv6 != nullptr)
        tmp++;
    return tmp;
}

void CCPSManager::createConnection(const QByteArray &IP, unsigned short port) {
    QHostAddress ip(IP);
    {
        QUdpSocket **udpTmp;
        char ipProtocol = 0;
        switch (ip.protocol()) {
            case QAbstractSocket::IPv4Protocol:
                udpTmp = &ipv4;
                ipProtocol = 1;
                break;
            case QAbstractSocket::IPv6Protocol:
                udpTmp = &ipv6;
                ipProtocol = 2;
                break;
            default:
                break;
        }
        if (ipProtocol == 0) {
            emit connectFail(ip, port, "IP不正确");
            return;
        }
        auto &udp = (*udpTmp);
        if (udp == nullptr) {
            emit connectFail(ip, port, "以目标IP协议所管理的CCPS管理器未启动");
            return;
        }
    }
    auto ipTmp = IPPort(QHostAddress(IP), port);
    if (ccps.exist(ipTmp)) {
        emit connected(ccps[ipTmp]);
        return;
    }
    if ((ccps.size() >= connectNum)) {
        emit connectFail(ip, port, "当前管理器连接的CCPS数量已达到上限");
        return;
    }
    if (!connecting.exist(ipTmp)) {
        auto tmp = new CCPS(this, QHostAddress(IP), port);
        connecting[ipTmp] = tmp;
        connect(tmp, &CCPS::connected_, this, &CCPSManager::connected_, Qt::QueuedConnection);
        connect(tmp, &CCPS::disconnected, this, &CCPSManager::connectFail_, Qt::QueuedConnection);
        tmp->connect_();
    }
}

QByteArray CCPSManager::udpError() const {
    return udpErrorInfo;
}

void CCPSManager::rmCCPS_() {
    auto c = (CCPS *) sender();
    if (c != nullptr) {
        auto ipPort = IPPort(c->IP, c->port);
        ccps.remove(ipPort);
        connecting.remove(ipPort);
        c->deleteLater();
    }
}

void CCPSManager::requestInvalid_(const QByteArray&) {
    auto c = (CCPS *) sender();
    ccps.remove(IPPort(c->IP, c->port));
    emit requestInvalid(c->IP, c->port);
    delete c;
}

void CCPSManager::recv_() {
    auto udp = (QUdpSocket*)sender();
    while (udp->hasPendingDatagrams()) {
        auto datagrams = udp->receiveDatagram();
        auto IP = datagrams.senderAddress();
        auto port = datagrams.senderPort();
        auto data = datagrams.data();
        if (data.size() >= 45)
            proc_(IP, port, data);
    }
}
