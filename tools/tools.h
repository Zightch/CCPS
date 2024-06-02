#pragma once

class QString;
class QHostAddress;
class QByteArray;

QString IPPort(const QHostAddress &, unsigned short);

QString bytesToHexString(const QByteArray &);

QByteArray hexStringToBytes(const QString &);

QByteArray dump(unsigned short);
