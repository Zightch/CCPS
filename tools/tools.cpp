#include "tools.h"
#include <QMutexLocker>
#include <QHostAddress>

QString IPPort(const QHostAddress &addr, unsigned short port) {
    QString ip = addr.toString();
    QString portStr = QString::number(port);
    auto protocol = addr.protocol();
    if (protocol == QAbstractSocket::IPv4Protocol)return ip + ":" + portStr;
    else if (protocol == QAbstractSocket::IPv6Protocol)return "[" + ip + "]:" + portStr;
    else return {};
}

QString BAToHex(const QByteArray &data) {
    QString hexString;
    for (char i: data)
        hexString += QString("%1 ").arg((quint8) i, 2, 16, QChar('0'));
    return hexString.trimmed();
}

QByteArray dump(unsigned short num) {
    QByteArray tmp0;
    char *tmp1 = (char *) &num;
    tmp0.append(tmp1[0]);
    tmp0.append(tmp1[1]);
    return tmp0;
}
