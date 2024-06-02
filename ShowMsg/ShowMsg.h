#pragma once
#include <QWidget>
#include "CCPS/CCPS.h"

QT_BEGIN_NAMESPACE
namespace Ui { class ShowMsg; }
QT_END_NAMESPACE

class ShowMsg : public QWidget {
Q_OBJECT

public:
    explicit ShowMsg(CCPS *, QWidget * = nullptr);

    ~ShowMsg() override;

    CCPS *getCCPS();
private:
    Ui::ShowMsg *ui;
    CCPS *ccps = nullptr;
    QString sendLastHexStr;
    QByteArrayList recvData;
private slots:
    void recv();
    void send();
    void hex(Qt::CheckState);
    void sendDataChange();
};
