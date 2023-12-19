#pragma once
#include <QUdpSocket>
#include <QMap>
#include "tools/Trie.hpp"

#ifdef _WIN32
#define CCPS_DLL __declspec(dllexport)
#elif __linux__
#define CCPS_DLL
#endif

class CCPS;

class CCPS_DLL CCPSManager : public QObject {
Q_OBJECT

public:
    explicit CCPSManager(QObject * = nullptr);

    ~CCPSManager() override;

    QByteArrayList bind(unsigned short);

    QByteArray bind(const QByteArray &, unsigned short);

    void setMaxConnectNum(unsigned long long);

    [[nodiscard]]
    unsigned long long getConnectNum();

    void createConnection(const QByteArray &, unsigned short);

    void close();

    int isBind();

    [[nodiscard]]
    QByteArray udpError() const;

public:
signals:

    void connectFail(const QHostAddress &, unsigned short, const QByteArray &);//我方主动连接连接失败

    void requestInvalid(const QHostAddress &, unsigned short);//对方请求连接连接无效

    void connected(void *);//连接成功(包含我方主动与对方请求)

private:
signals:

    void sendS_(const QHostAddress &, unsigned short, const QByteArray &);

private:
    void proc_(const QHostAddress &, unsigned short, const QByteArray &);

    void sendF_(const QHostAddress &, unsigned short, const QByteArray &);

    void connectFail_(const QByteArray &);

    void connected_();

    void rmCCPS_();

    void requestInvalid_(const QByteArray &);

    void recv_();

    Trie<CCPS *> ccps;//已连接的
    unsigned long long connectNum = 65535;//最大连接数量
    Trie<CCPS *> connecting;//连接中的ccps
    QUdpSocket *ipv4 = nullptr;
    QUdpSocket *ipv6 = nullptr;
    QByteArray udpErrorInfo;

    friend class CCPS;
};
