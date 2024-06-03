#pragma once

#include <QDialog>

class CCPSManager;

QT_BEGIN_NAMESPACE
namespace Ui { class SetCert; }
QT_END_NAMESPACE

class SetCert : public QDialog {
Q_OBJECT

public:
    explicit SetCert(CCPSManager *cm, QWidget *parent = nullptr);

    ~SetCert() override;

private:
    Ui::SetCert *ui;
    CCPSManager *cm = nullptr;
    QString lastServerCrtPath;
    QString lastServerKeyPath;
    QString lastVerifyClientCrtPath;
    QString lastClientCrtPath;
    QString lastClientKeyPath;
    QString lastVerifyServerCrtPath;
    void closeEvent(QCloseEvent *e) override;
private slots:
    void select();
    void OK();
    void cancel();
};
