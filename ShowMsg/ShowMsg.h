#pragma once
#include <QWidget>

class CFUPS;

QT_BEGIN_NAMESPACE
namespace Ui { class ShowMsg; }
QT_END_NAMESPACE

class ShowMsg : public QWidget {
Q_OBJECT

public:
    explicit ShowMsg(CFUPS *, QWidget * = nullptr);

    ~ShowMsg() override;

    CFUPS *getCFUPS();
private:
    Ui::ShowMsg *ui;
    CFUPS *cfups = nullptr;
    QString sendLastHexStr;
    QByteArrayList recvData;
private slots:
    void recv();
    void send();
    void hex(Qt::CheckState);
    void sendDataChange();
};
