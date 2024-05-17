#pragma once

class QString;
class QHostAddress;
class QByteArray;

QString IPPort(const QHostAddress &, unsigned short);

QString BAToHex(const QByteArray &);

QByteArray dump(unsigned short);
