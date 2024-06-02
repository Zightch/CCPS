#include "CCPSTest.h"
#include "./ui_CCPSTest.h"
#include <QMessageBox>
#include "tools/tools.h"

CCPSTest::CCPSTest(QWidget *parent) : QWidget(parent), ui(new Ui::CCPSTest) {
    ui->setupUi(this);
    newConnect = new NewConnect();
    connect(ui->bind, &QPushButton::clicked, this, &CCPSTest::bind);
    connect(ui->connectList, &QListWidget::itemSelectionChanged, this, &CCPSTest::enableOperateBtn);
    connect(ui->showMsg, &QPushButton::clicked, this, &CCPSTest::showMsg);
    connect(ui->closeConnect, &QPushButton::clicked, this, &CCPSTest::closeConnect);
    connect(ui->newConnect, &QPushButton::clicked, newConnect, &NewConnect::show);
    connect(newConnect, &NewConnect::toConnect, this, &CCPSTest::toConnect);
}

CCPSTest::~CCPSTest() {
    delete ui;
}

void CCPSTest::bind() {
    auto uiCTRL = [this](bool i) {
        ui->localIP->setEnabled(!i);
        ui->localPort->setEnabled(!i);
        ui->connectList->setEnabled(i);
        ui->newConnect->setEnabled(i);
    };
    if (ccpsManager == nullptr) {
        ccpsManager = new CCPSManager(this);
        QStringList error;
        auto ipStr = ui->localIP->text().toLocal8Bit();
        if (ipStr.isEmpty())error = ccpsManager->bind(ui->localPort->value());
        else {
            auto ret = ccpsManager->bind(ipStr, ui->localPort->value());
            if (!ret.isEmpty())error.append(ret);
        }
        if (error.isEmpty()) {
            ui->bind->setText("关闭");
            uiCTRL(true);
            connect(ccpsManager, &CCPSManager::connected, this, &CCPSTest::connected);
            connect(ccpsManager, &CCPSManager::connectFail, this, &CCPSTest::connectFail);
            connect(ccpsManager, &CCPSManager::cLog, this, &CCPSTest::appendLog);
        } else {
            QString tmp;
            for (const auto &i: error)tmp += (i + "\n");
            QMessageBox::information(this, "绑定失败", tmp.trimmed());
            ccpsManager->quit();
            ccpsManager = nullptr;
        }
    } else {
        ccpsManager->quit();
        ccpsManager = nullptr;
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

void CCPSTest::closeConnect() {
    auto item = ui->connectList->currentItem();
    auto client = connectList[item->text()];
    client->getCCPS()->close();
}

void CCPSTest::enableOperateBtn() {
    ui->showMsg->setEnabled(true);
    ui->closeConnect->setEnabled(true);
}

void CCPSTest::connected(CCPS *ccps) {
    //在客户端列表里添加一个元素(IP:port)
    auto ipPort = IPPort(ccps->getIP(), ccps->getPort());
    if (!connectList.contains(ipPort)) {
        ui->connectList->addItem(ipPort);
        //去构造一个ShowMsg窗口, 以备显示
        auto sm = new ShowMsg(ccps);
        //Map保存所有客户端(ShowMsg)
        connectList.insert(ipPort, sm);
        connect(ccps, &CCPS::disconnected, this, &CCPSTest::disconnected);
    }
    {
        QByteArray IP;
        unsigned short port;
        newConnect->getTmpIPPort(IP, port);
        if (ipPort == IPPort(QHostAddress(IP), port)) {
            newConnect->restoreUI();
            newConnect->close();
        }
    }
}

void CCPSTest::showMsg() {
    auto ipPort = ui->connectList->currentItem()->text();
    connectList[ipPort]->show();
}

void CCPSTest::disconnected() {
    auto ccps = (CCPS *) sender();
    auto ipPort = IPPort(ccps->getIP(), ccps->getPort());
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

void CCPSTest::appendLog(const QString &data) {
    ui->logger->appendPlainText(data);
}

void CCPSTest::connectFail(const QHostAddress &IP, unsigned short port, const QByteArray &data) {
    newConnect->restoreUI();
    QMessageBox::information(newConnect, IPPort(IP, port) + " 连接失败", data);
}

void CCPSTest::toConnect(const QByteArray &IP, unsigned short port) {
    if (ccpsManager != nullptr)
        ccpsManager->connectToHost(IP, port);
}

void CCPSTest::closeEvent(QCloseEvent *e) {
    if (ccpsManager != nullptr)ccpsManager->quit();
    ccpsManager = nullptr;
    if (newConnect != nullptr) newConnect->deleteLater();
    newConnect = nullptr;
    QWidget::closeEvent(e);
}
