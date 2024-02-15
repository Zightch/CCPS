#pragma once
#include <QTimer>
#include <QMap>
#include <QHostAddress>
#include <QException>

#ifdef _WIN32
#define CCPS_DLL __declspec(dllexport)
#elif __linux__
#define CCPS_DLL
#endif

class CCPSManager;
class CDPT;

//CCPS协议对象类(实现)
class CCPS_DLL CCPS : public QObject {
Q_OBJECT

public:
    void close(const QByteArray & = "");

    void sendNow(const QByteArray &);

    void send(const QByteArray &);

    [[nodiscard]]
    bool hasData() const;

    QByteArray read();

    void setDataBlockSize(unsigned short);

    void setHBTTime(unsigned short);

    void setTimeout(unsigned short);

    void setRetryNum(unsigned char);

    [[nodiscard]]
    QHostAddress getIP() const;

    [[nodiscard]]
    unsigned short getPort() const;

signals:
    void disconnected(const QByteArray & = "");

    void readyRead();

    void procS_(const QByteArray &);

    void deleteRedelay_();

    void connected_();

    void disconnectedForCM_(const QByteArray &);


private:
    explicit CCPS(QObject *, const QHostAddress &, unsigned short);

    ~CCPS() override;

    void connect_();

    void procF_(const QByteArray &);

    void sendTimeout_();

    void sendPackage_(CDPT *);

    void NA_ACK(unsigned short AID, const QByteArray & = "");//应答

    void updateWnd_();//更新窗口

    void transmitShunt_(CDPT *);

    struct CCPSDP {//纯数据
        unsigned char cf = 0;//属性和命令
        unsigned short SID = 0;//本包ID
        QByteArray data = "";//用户数据
    };

    CCPSManager *cm = nullptr;//CCPSManager
    char cs = -1;//-1未连接, 0半连接, 1连接成功
    unsigned short ID = 0;//自己的包ID
    unsigned short OID = -1;//对方当前包ID
    QMap<unsigned short, CDPT *> sendWnd;//发送窗口
    QMap<unsigned short, CCPSDP> recvWnd;//接收窗口
    QList<CDPT *> sendBuf;//发送缓存
    QByteArrayList readBuf;//可读缓冲区
    bool link = false;
    unsigned short linkStart = 0;
    unsigned short dataBlockSize = 1024;
    QTimer hbt;//心跳包定时器
    unsigned short timeout = 1000;//数据包超时时间
    unsigned char retryNum = 2;//重发次数
    unsigned short hbtTime = 10000;//心跳时间
    QHostAddress IP;//远程主机IP
    unsigned short port;//远程主机port
    bool initiative = false;//主动性

    void *key = nullptr;//X25519密钥对
    QByteArray sharedKey;//共享密钥
    unsigned char IV[16] = {0};//IV数组

    friend class CCPSManager;

    friend class CDPT;
};

//CCPS发送数据包继承定时器(定义)
class CDPT : public QTimer, public CCPS::CCPSDP {
Q_OBJECT

public:
    explicit CDPT(QObject *);

    ~CDPT() override;

    unsigned char retryNum = 0;//重发次数
    unsigned short AID = 0;//应答包ID
};
