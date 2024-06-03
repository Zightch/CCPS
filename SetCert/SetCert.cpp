#include "SetCert.h"
#include "ui_SetCert.h"
#include "CCPS/CCPSManager.h"
#include <QFileDialog>
#include <QMessageBox>

SetCert::SetCert(CCPSManager *cm, QWidget *parent) : QDialog(parent), ui(new Ui::SetCert), cm(cm) {
    ui->setupUi(this);

    lineEdits[0] = ui->serverCrt;
    lineEdits[1] = ui->serverKey;
    lineEdits[2] = ui->verifyClientCrt;
    lineEdits[3] = ui->clientCrt;
    lineEdits[4] = ui->clientKey;
    lineEdits[5] = ui->verifyServerCrt;

    btns[0] = ui->selectServerCrtBtn;
    btns[1] = ui->selectServerKeyBtn;
    btns[2] = ui->selectVerifyClientCrtBtn;
    btns[3] = ui->selectClientCrtBtn;
    btns[4] = ui->selectClientKeyBtn;
    btns[5] = ui->selectVerifyServerCrtBtn;

    for (auto i: btns)
        connect(i, &QPushButton::clicked, this, &SetCert::select);

    connect(ui->OK, &QPushButton::clicked, this, &SetCert::OK);
    connect(ui->cancel, &QPushButton::clicked, this, &SetCert::cancel);
}

SetCert::~SetCert() {
    delete ui;
}

void SetCert::select() {
    auto btn = (QPushButton *) sender();
    QString filePath = QFileDialog::getOpenFileName(this, "选择文件", {}, "所有文件(*.*)");
    if (filePath.isEmpty())return;
    for (int i = 0; i < 6; i++)
        if (btn == btns[i])
            lineEdits[i]->setText(filePath);
}

void SetCert::OK() {
    // 读取内容
    QString errors;
    QByteArray tmp[6];
    for (int i = 0; i < 6; i++) {
        auto filePath = lineEdits[i]->text();
        if (filePath.isEmpty())continue;
        QFile file(filePath);
        if (!file.open(QFile::ReadOnly)) {
            errors += filePath + " 文件打开失败: " + file.errorString() + "\n";
            continue;
        }
        tmp[i] = file.readAll();
        file.close();
    }
    if (!errors.isEmpty()) {
        QMessageBox::information(this, "文件打开失败", errors);
        return;
    }
    if (tmp[0].isEmpty() ^ tmp[1].isEmpty())errors += "服务器证书: 必须同时指定证书和私钥\n";
    if (!(!tmp[3].isEmpty() ^ tmp[4].isEmpty()))errors += "客户端证书: 必须同时指定证书和私钥\n";
    if (!errors.isEmpty()) {
        QMessageBox::information(this, "证书错误", errors);
        return;
    }
    QString error;
    error = cm->setServerCrtAndKey(tmp[0], tmp[1]);
    if (!error.isEmpty())errors += error + "\n";
    error = cm->setVerifyClientCrt(tmp[2]);
    if (!error.isEmpty())errors += error + "\n";
    error = cm->setClientCrtAndKey(tmp[3], tmp[4]);
    if (!error.isEmpty())errors += error + "\n";
    error = cm->setVerifyServerCrt(tmp[5]);
    if (!error.isEmpty())errors += error + "\n";
    if (!errors.isEmpty()) {
        QMessageBox::information(this, "证书错误", errors);
        return;
    }
    for (int i = 0; i < 6; i++)
        lastPaths[i] = lineEdits[i]->text();
    accept();
}

void SetCert::cancel() {
    for (int i = 0; i < 6; i++)
        lineEdits[i]->setText(lastPaths[i]);
    reject();
}

void SetCert::closeEvent(QCloseEvent *e) {
    cancel();
    QDialog::closeEvent(e);
}
