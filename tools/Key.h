#pragma once

#include <openssl/types.h>

class QByteArray;

void *genX25519Key();
QByteArray getPubKey(void *);
QByteArray genSharedKey(void *, const QByteArray &);
QByteArray encryptData(const QByteArray &, unsigned char [16], const QByteArray &);
QByteArray decryptData(const QByteArray &, unsigned char [16], const QByteArray &);

unsigned long long checksum0(const QByteArray &);
int checksum1(const QByteArray &);
QByteArray checksums(const QByteArray &);
