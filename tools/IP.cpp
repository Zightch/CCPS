#include "IP.h"
#include <QMutexLocker>
#include <QRegularExpression>
#include <QHostAddress>

namespace IPTools {
    QMutex IPPort;
}

QByteArray IPPort(const QHostAddress &addr, unsigned short port) {
    QMutexLocker ml(&IPTools::IPPort);
    QByteArray tmp = "";
    QByteArray ip = addr.toString().toLocal8Bit();
    QByteArray portStr = QString::number(port).toLocal8Bit();
    switch (addr.protocol()) {
        case QAbstractSocket::IPv4Protocol:
            tmp = ip + ":" + portStr;
            break;
        case QAbstractSocket::IPv6Protocol:
            tmp = "[" + ip + "]:" + portStr;
            break;
        default:
            break;
    }
    return tmp;
}
