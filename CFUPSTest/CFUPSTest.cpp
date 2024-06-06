#include "CFUPSTest.h"
#include "./ui_CFUPSTest.h"
#include <QMessageBox>
#include "tools/tools.h"
#include "CFUPS/CFUPSManager.h"
#include "CFUPS/CFUPS.h"

CFUPSTest::CFUPSTest(QWidget *parent) : QWidget(parent), ui(new Ui::CFUPSTest) {
    ui->setupUi(this);
    cm = new CFUPSManager(this);
    setCert = new SetCert(cm);
    connect(ui->bind, &QPushButton::clicked, this, &CFUPSTest::bind);
    connect(ui->connectList, &QListWidget::itemSelectionChanged, this, &CFUPSTest::enableOperateBtn);
    connect(ui->showMsg, &QPushButton::clicked, this, &CFUPSTest::showMsg);
    connect(ui->closeConnect, &QPushButton::clicked, this, &CFUPSTest::closeConnect);
    connect(ui->newConnect, &QPushButton::clicked, &newConnect, &NewConnect::show);
    connect(ui->crtBtn, &QPushButton::clicked, setCert, &SetCert::exec);
    connect(&newConnect, &NewConnect::toConnect, this, &CFUPSTest::toConnect);
}

CFUPSTest::~CFUPSTest() {
    delete ui;
}

void CFUPSTest::bind() {
    auto uiCTRL = [this](bool i) {
        ui->localIP->setEnabled(!i);
        ui->localPort->setEnabled(!i);
        ui->crtBtn->setEnabled(!i);
        ui->connectList->setEnabled(i);
        ui->newConnect->setEnabled(i);
    };
    if (cm->isBind() == 0) {
        QStringList error;
        auto ipStr = ui->localIP->text().toLocal8Bit();
        if (ipStr.isEmpty())error = cm->bind(ui->localPort->value());
        else {
            auto ret = cm->bind(ipStr, ui->localPort->value());
            if (!ret.isEmpty())error.append(ret);
        }
        if (error.isEmpty()) {
            ui->bind->setText("关闭");
            uiCTRL(true);
            connect(cm, &CFUPSManager::connected, this, &CFUPSTest::connected);
            connect(cm, &CFUPSManager::connectFail, this, &CFUPSTest::connectFail);
            connect(cm, &CFUPSManager::cLog, this, &CFUPSTest::appendLog);
        } else {
            QString tmp;
            for (const auto &i: error)tmp += (i + "\n");
            QMessageBox::information(this, "绑定失败", tmp.trimmed());
            cm->close();
        }
    } else {
        cm->close();
        ui->connectList->clear();
        for (auto i: connectList)
            delete i;
        connectList.clear();
        ui->bind->setText("绑定");
        uiCTRL(false);
        ui->closeConnect->setEnabled(false);
        ui->showMsg->setEnabled(false);
    }
}

void CFUPSTest::closeConnect() {
    auto item = ui->connectList->currentItem();
    auto client = connectList[item->text()];
    client->getCFUPS()->close();
}

void CFUPSTest::enableOperateBtn() {
    ui->showMsg->setEnabled(true);
    ui->closeConnect->setEnabled(true);
}

void CFUPSTest::connected(CFUPS *cfups) {
    //在客户端列表里添加一个元素(IP:port)
    auto ipPort = IPPort(cfups->getIP(), cfups->getPort());
    if (!connectList.contains(ipPort)) {
        ui->connectList->addItem(ipPort);
        //去构造一个ShowMsg窗口, 以备显示
        auto sm = new ShowMsg(cfups);
        //Map保存所有客户端(ShowMsg)
        connectList.insert(ipPort, sm);
        connect(cfups, &CFUPS::disconnected, this, &CFUPSTest::disconnected);
    }
    {
        QByteArray IP;
        unsigned short port;
        newConnect.getTmpIPPort(IP, port);
        if (ipPort == IPPort(QHostAddress(IP), port)) {
            newConnect.restoreUI();
            newConnect.close();
        }
    }
}

void CFUPSTest::showMsg() {
    auto ipPort = ui->connectList->currentItem()->text();
    connectList[ipPort]->show();
}

void CFUPSTest::disconnected() {
    auto cfups = (CFUPS *) sender();
    auto ipPort = IPPort(cfups->getIP(), cfups->getPort());
    //窗口
    auto client = connectList[ipPort];
    delete client;
    connectList.remove(ipPort);
    //客户端列表
    for (auto i = ui->connectList->count() - 1; i >= 0; i--) {
        auto item = ui->connectList->item(i);
        if (item->text() == ipPort) {
            ui->connectList->removeItemWidget(item);
            delete item;
            break;
        }
    }
    if (ui->connectList->count() == 0) {
        ui->closeConnect->setEnabled(false);
        ui->showMsg->setEnabled(false);
    }
}

void CFUPSTest::appendLog(const QString &data) {
    ui->logger->appendPlainText(data);
}

void CFUPSTest::connectFail(const QHostAddress &IP, unsigned short port, const QByteArray &data) {
    newConnect.restoreUI();
    QMessageBox::information(&newConnect, IPPort(IP, port) + " 连接失败", data);
}

void CFUPSTest::toConnect(const QByteArray &IP, unsigned short port) {
    if (cm->isBind() > 0)
        cm->connectToHost(IP, port);
}

void CFUPSTest::closeEvent(QCloseEvent *e) {
    if (cm != nullptr)cm->quit();
    cm = nullptr;
    newConnect.close();
    if (setCert != nullptr)setCert->deleteLater();
    setCert = nullptr;
    QWidget::closeEvent(e);
}
