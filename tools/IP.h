#pragma once

#ifdef _WIN32
#define CCPS_DLL __declspec(dllexport)
#elif __linux__
#define CCPS_DLL
#endif

class QByteArray;
class QHostAddress;

QByteArray CCPS_DLL IPPort(const QHostAddress &, unsigned short);
