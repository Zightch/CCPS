#pragma once

#include <QHostAddress>
#include <QObject>
#include <QHash>

class CCPS;
class QUdpSocket;

class CCPSManager final : public QObject {
Q_OBJECT

public:
    explicit CCPSManager(QObject * = nullptr);

    QString bind(const QString &, unsigned short); // 绑定

    QStringList bind(unsigned short); // 绑定

    void setMaxConnectNum(int); // 设置最大连接数量

    int getMaxConnectNum(); // 获取最大连接数量

    int getConnectedNum(); // 获取已连接数量

    int isBind(); // 已经绑定, 0表示无绑定, 1表示只绑定了IPv4, 2表示只绑定了IPv6, 3表示IPv4和IPv6都绑定了

    void connectToHost(const QString &, unsigned short);

    void connectToHost(const QHostAddress &, unsigned short);

    bool setServerCrtAndKey(const QByteArray &, const QByteArray &); // 设置服务器证书和密钥

    bool setVerifyClientCrt(const QByteArray &); // 设置验证客户端的证书(如果设置表示验证客户端)

    bool setClientCrtAndKey(const QByteArray &, const QByteArray &); // 设置客户端的证书和密钥

    bool setVerifyServerCrt(const QByteArray &); // 设置验证服务端的证书(如果设置表示验证服务端)

signals:

    void connectFail(const QHostAddress &, unsigned short, const QByteArray &); // 我方主动连接连接失败

    void connected(CCPS *); // 连接成功(包含我方主动与对方请求)

    void cLog(const QString &);

public slots:

    void close(); // 这个只是关闭管理器

    void quit(); // delete调用它
private slots:

    void deleteLater();

    void recv_(); // 接收数据

    void rmCCPS_();

private:
    QHash<QString, CCPS *> ccps; // 已连接的
    int connectNum = 65535; // 最大连接数量
    QHash<QString, CCPS *> connecting; // 连接中的ccps
    QUdpSocket *ipv4 = nullptr;
    QUdpSocket *ipv6 = nullptr;
    bool isBindAll = false; // 判断是否是调用的QStringList bind(unsigned short);函数

    ~CCPSManager() override;

    void proc_(const QHostAddress &, unsigned short, const QByteArray &); // 处理来的信息

    void send_(const QHostAddress &, unsigned short, const QByteArray &); // 发送数据

    bool threadCheck_(const QString &); // 线程检查

    void ccpsConnected_(CCPS *);

    void requestInvalid_(const QByteArray &);

    friend class CCPS;
};
