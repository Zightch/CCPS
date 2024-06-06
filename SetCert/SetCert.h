#pragma once

#include <QDialog>

class CFUPSManager;
class QLineEdit;

QT_BEGIN_NAMESPACE
namespace Ui { class SetCert; }
QT_END_NAMESPACE

class SetCert : public QDialog {
Q_OBJECT

public:
    explicit SetCert(CFUPSManager *cm, QWidget *parent = nullptr);

    ~SetCert() override;

private:
    Ui::SetCert *ui;
    CFUPSManager *cm = nullptr;
    QLineEdit *lineEdits[6] = {nullptr};
    QPushButton *btns[6] = {nullptr};

    QString lastPaths[6];

    void closeEvent(QCloseEvent *e) override;

private slots:

    void select();

    void OK();

    void cancel();
};
