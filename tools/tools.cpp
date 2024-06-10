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

QString bytesToHexString(const QByteArray &data) {
    QString hexString;
    for (char i: data)
        hexString += QString("%1 ").arg((quint8) i, 2, 16, QChar('0'));
    return hexString.trimmed();
}

QByteArray dump(unsigned short num) {
    QByteArray tmp;
    tmp.resize(2);
    *(unsigned short *) tmp.data() = num;
    return tmp;
}

QByteArray dump(long long num) {
    QByteArray tmp;
    tmp.resize(8);
    *(long long *) tmp.data() = num;
    return tmp;
}

QByteArray hexStringToBytes(const QString &str) {
    QByteArray data;
    auto items = str.split(" ", Qt::SkipEmptyParts);
    for (const auto &i: items) {
        if (i.size() != 2)return {};
        auto first = i[0].unicode();
        auto second = i[1].unicode();
        char item = 0;
        if ('0' <= first && first <= '9')item = (char) (first - 48);
        else if ('A' <= first && first <= 'F')item = (char) (first - 55);
        else if ('a' <= first && first <= 'f')item = (char) (first - 87);
        else return {};
        item &= 0x0F;
        item <<= 4;
        if ('0' <= second && second <= '9')item = (char) (item | (second - 48));
        else if ('A' <= second && second <= 'F')item = (char) (item | (second - 55));
        else if ('a' <= second && second <= 'f')item = (char) (item | (second - 87));
        else return {};
        data.append(item);
    }
    return data;
}
