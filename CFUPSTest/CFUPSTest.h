#pragma once

#include <QWidget>
#include <QHostAddress>
#include "ShowMsg/ShowMsg.h"
#include "NewConnect/NewConnect.h"
#include "SetCert/SetCert.h"

class CFUPSManager;

QT_BEGIN_NAMESPACE
namespace Ui { class CFUPSTest; }
QT_END_NAMESPACE

class CFUPSTest : public QWidget {
Q_OBJECT

public:
    explicit CFUPSTest(QWidget * = nullptr);

    ~CFUPSTest() override;

private:
    Ui::CFUPSTest *ui = nullptr;
    CFUPSManager *cm = nullptr;
    NewConnect newConnect;
    SetCert *setCert = nullptr;

    void bind();

    void enableOperateBtn();

    void connected(CFUPS *);

    void showMsg();

    void closeConnect();

    void disconnected();

    void appendLog(const QString &);

    void connectFail(const QHostAddress &, unsigned short, const QByteArray &);

    void toConnect(const QByteArray &, unsigned short);

    QMap<QString, ShowMsg *> connectList;

    void closeEvent(QCloseEvent *) override;
};
