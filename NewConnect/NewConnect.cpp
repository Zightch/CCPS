#include "NewConnect.h"
#include "ui_NewConnect.h"

NewConnect::NewConnect(QWidget *parent) : QWidget(parent), ui(new Ui::NewConnect) {
    ui->setupUi(this);
    connect(ui->connect, &QPushButton::clicked, this, &NewConnect::toConnect_);
}

NewConnect::~NewConnect() {
    delete ui;
}

void NewConnect::toConnect_() {
    ui->connect->setText("连接中...");
    ui->connect->setEnabled(false);
    ui->IP->setEnabled(false);
    ui->port->setEnabled(false);
    tmpIP = ui->IP->text().toUtf8();
    tmpPort = ui->port->value();
    emit toConnect(tmpIP, tmpPort);
}

void NewConnect::restoreUI() {
    ui->connect->setText("连接");
    ui->connect->setEnabled(true);
    ui->IP->setEnabled(true);
    ui->port->setEnabled(true);
    tmpIP.clear();
    tmpPort = -1;
}

void NewConnect::getTmpIPPort(QByteArray &IP, unsigned short &port) {
    IP = tmpIP;
    port = tmpPort;
}
