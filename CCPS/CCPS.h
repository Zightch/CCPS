#pragma once

#include <QTimer>
#include <QHash>
#include <QHostAddress>

class CCPSManager;
class CDPT;

//CCPS协议对象类(实现)
class CCPS final : public QObject {
Q_OBJECT

public:
    QHostAddress getIP();

    unsigned short getPort();

    void close(const QByteArray & = {});

    void send(const QByteArray &);

    void sendNow(const QByteArray &);

    QByteArray nextPendingData();

    bool hasData();

    QByteArrayList readAll();

public slots:

signals:

    void disconnected(const QByteArray & = {});

    void readyRead();

private slots:

    void sendTimeout_();

private:
    class CCPSDP {//纯数据
    public:
        unsigned char cf = 0;//属性和命令
        unsigned short SID = 0;//本包ID
        QByteArray data{};//用户数据
    };

    CCPSManager *cm = nullptr; // CCPSManager
    char cs = -1; // -1未连接, 0半连接, 1三次握手完成, 2已连接, 3已断开
    unsigned short ID = 0; // 自己的包ID
    unsigned short OID = -1; // 对方当前包ID

    QHash<unsigned short, CDPT *> sendWnd; // 发送窗口
    QHash<unsigned short, CCPSDP> recvWnd; // 接收窗口
    QList<CDPT *> sendBufLv1; // 发送1级缓存
    QByteArrayList readBuf; // 可读缓存
    QByteArrayList sendBufLv2; // 发送2级缓存
    QByteArray recvBuf; // 接收缓存
    // 外部发送 -> 发送2级缓存 -> 发送1级缓存 -> 发送窗口 -> 发送
    // 接收 -> 接收窗口 -> 接收缓存 -> 可读缓存 -> 准备好读取
    // NA数据包不需要走发送缓存和发送窗口, 直接发送

    unsigned short wndSize = 256; // 窗口大小, 最大65533
    unsigned short dataBlockSize = 13; // 可靠传输时数据块大小, 测试用13, 生产环境默认1013, 最大65476
    QTimer hbt; // 心跳包定时器
    unsigned short hbtTime = 15000; // 心跳时间
    QHostAddress IP; // 远程主机IP
    unsigned short port; // 远程主机port
    bool initiative = false; // 主动性
    unsigned short timeout = 1000; // 超时时间
    unsigned char retryNum = 2; // 重试次数

    QByteArray localCrt; // 本地证书
    QByteArray localKey; // 本地私钥
    QByteArray peerCrt; // 对端证书
    QByteArray CA; // 用于验证对端的CA证书
    QByteArray sharedKey; // 共享密钥
    QByteArray IV; // IV数组
    QTimer sexticTiming; // 6次握手定时器

    explicit CCPS(CCPSManager *, const QHostAddress &, unsigned short);

    ~CCPS() override;

    bool threadCheck_(const QString &); // 线程检查

    void proc_(QByteArray); // 处理来者信息

    void connectToHost_(); // 连接到主机

    void updateWnd_(); // 更新窗口

    void updateSendBuf_(); // 更新发送缓存

    void sendPackage_(CDPT *); // 返回值是NA

    CDPT *newCDPT_(); // new一个CDPT

    void NA_ACK_(unsigned short, const QByteArray & = {});

    bool tryGenKeyPair_();

    bool verify_();

    void cmdRC_(const QByteArray &);

    void cmdACK_(bool, bool, const QByteArray &);

    void cmdRC_ACK_(bool, bool, const QByteArray &);

    void cmdC_(bool, bool, const QByteArray &);

    void cmdH_(bool, const QByteArray &);

    friend class CCPSManager;

    friend class CDPT;
};

//CCPS数据包+定时器(定义)
class CDPT : public QTimer, public CCPS::CCPSDP {
Q_OBJECT

private:
    explicit CDPT(QObject *);

    ~CDPT() override;

    unsigned char retryNum = 0;//重发次数
    unsigned short AID = 0;//应答包ID
    bool isNotEncrypt = false;//该数据包不加密
    friend class CCPS;
};
