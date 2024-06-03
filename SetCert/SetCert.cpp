#include "SetCert.h"
#include "ui_SetCert.h"
#include "CCPS/CCPSManager.h"

SetCert::SetCert(CCPSManager *cm, QWidget *parent) : QDialog(parent), ui(new Ui::SetCert), cm(cm) {
    ui->setupUi(this);
    connect(ui->selectServerCrtBtn, &QPushButton::clicked, this, &SetCert::select);
    connect(ui->selectServerKeyBtn, &QPushButton::clicked, this, &SetCert::select);
    connect(ui->selectVerifyClientCrtBtn, &QPushButton::clicked, this, &SetCert::select);
    connect(ui->selectClientCrtBtn, &QPushButton::clicked, this, &SetCert::select);
    connect(ui->selectClientKeyBtn, &QPushButton::clicked, this, &SetCert::select);
    connect(ui->selectVerifyServerCrtBtn, &QPushButton::clicked, this, &SetCert::select);
    connect(ui->OK, &QPushButton::clicked, this, &SetCert::OK);
    connect(ui->cancel, &QPushButton::clicked, this, &SetCert::cancel);
}

SetCert::~SetCert() {
    delete ui;
}

void SetCert::select() {
    auto btn = (QPushButton *) sender();
    // TODO
}

void SetCert::OK() {
    // TODO
    accept();
}

void SetCert::cancel() {
    ui->serverCrt->setText(lastServerCrtPath);
    ui->serverKey->setText(lastServerKeyPath);
    ui->verifyClientCrt->setText(lastVerifyClientCrtPath);
    ui->clientCrt->setText(lastClientCrtPath);
    ui->clientKey->setText(lastClientKeyPath);
    ui->verifyServerCrt->setText(lastVerifyServerCrtPath);
    reject();
}

void SetCert::closeEvent(QCloseEvent *e) {
    cancel();
    QDialog::closeEvent(e);
}
