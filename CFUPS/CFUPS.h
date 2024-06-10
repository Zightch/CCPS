#pragma once

#include <QTimer>
#include <QHash>
#include <QHostAddress>

class CFUPSManager;
class CDPT;

//CFUPS协议对象类(实现)
class CFUPS final : public QObject {
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
    class CFUPSDP {//纯数据
    public:
        unsigned char cf = 0;//属性和命令
        unsigned short SID = 0;//本包ID
        QByteArray data{};//用户数据
    };

    CFUPSManager *cm = nullptr; // CFUPSManager
    char cs = -1; // -1未连接, 0半连接, 1三次握手完成, 2已连接, 3已断开
    unsigned short ID = 0; // 自己的包ID
    unsigned short OID = -1; // 对方当前包ID

    QHash<unsigned short, long long> recvLastTime; // 接收窗口历史接收到的最大的时间
    QHash<unsigned short, CDPT *> sendWnd; // 发送窗口
    QHash<unsigned short, CFUPSDP> recvWnd; // 接收窗口
    QList<CDPT *> sendBufLv1; // 发送1级缓存
    QByteArrayList readBuf; // 可读缓存
    QByteArrayList sendBufLv2; // 发送2级缓存
    QByteArray recvBuf; // 接收缓存
    // 外部发送 -> 发送2级缓存 -> 发送1级缓存 -> 发送窗口 -> 发送
    // 接收 -> 接收窗口 -> 接收缓存 -> 可读缓存 -> 准备好读取
    // NA数据包不需要走发送缓存和发送窗口, 直接发送

    unsigned short wndSize = 96; // 窗口大小, 最大65533
    unsigned short dataBlockSize = 965; // 可靠传输时数据块大小, 测试用13, 生产环境默认965, 最大65476
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
    QSet<QByteArray> localRandSet; // 本地随机数集合
    QSet<QByteArray> peerRandSet; // 对方随机数集合

    explicit CFUPS(CFUPSManager *, const QHostAddress &, unsigned short);

    ~CFUPS() override;

    bool threadCheck_(const QString &); // 线程检查

    void proc_(QByteArray); // 处理来者信息

    void connectToHost_(); // 连接到主机

    void updateWnd_(); // 更新窗口

    void updateSendBuf_(); // 更新发送缓存

    void sendPackage_(CDPT *); // 返回值是NA

    CDPT *newCDPT_(); // new一个CDPT

    void NA_ACK_(unsigned short);

    bool tryGenKeyPair_();

    bool verify_();

    void cmdRC_(const QByteArray &);

    void cmdACK_(bool, const QByteArray &);

    void cmdRC_ACK_(bool, bool, const QByteArray &);

    void cmdC_(bool, bool, const QByteArray &);

    void cmdH_(bool, const QByteArray &);

    bool time_(unsigned short, long long);

    friend class CFUPSManager;

    friend class CDPT;
};

//CFUPS数据包+定时器(定义)
class CDPT : public QTimer, public CFUPS::CFUPSDP {
Q_OBJECT

private:
    explicit CDPT(QObject *);

    ~CDPT() override;

    unsigned char retryNum = 0;//重发次数
    unsigned short AID = 0;//应答包ID
    bool isNotEncrypt = false;//该数据包不加密
    friend class CFUPS;
};
