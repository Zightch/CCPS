#include "CCPSTest.h"
#include "./ui_CCPSTest.h"
#include <QMessageBox>
#include "tools/tools.h"
#include "CCPS/CCPSManager.h"
#include "CCPS/CCPS.h"

CCPSTest::CCPSTest(QWidget *parent) : QWidget(parent), ui(new Ui::CCPSTest) {
    ui->setupUi(this);
    cm = new CCPSManager(this);
    setCert = new SetCert(cm);
    connect(ui->bind, &QPushButton::clicked, this, &CCPSTest::bind);
    connect(ui->connectList, &QListWidget::itemSelectionChanged, this, &CCPSTest::enableOperateBtn);
    connect(ui->showMsg, &QPushButton::clicked, this, &CCPSTest::showMsg);
    connect(ui->closeConnect, &QPushButton::clicked, this, &CCPSTest::closeConnect);
    connect(ui->newConnect, &QPushButton::clicked, &newConnect, &NewConnect::show);
    connect(ui->crtBtn, &QPushButton::clicked, setCert, &SetCert::exec);
    connect(&newConnect, &NewConnect::toConnect, this, &CCPSTest::toConnect);
}

CCPSTest::~CCPSTest() {
    delete ui;
}

void CCPSTest::bind() {
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
            connect(cm, &CCPSManager::connected, this, &CCPSTest::connected);
            connect(cm, &CCPSManager::connectFail, this, &CCPSTest::connectFail);
            connect(cm, &CCPSManager::cLog, this, &CCPSTest::appendLog);
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
        newConnect.getTmpIPPort(IP, port);
        if (ipPort == IPPort(QHostAddress(IP), port)) {
            newConnect.restoreUI();
            newConnect.close();
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
    newConnect.restoreUI();
    QMessageBox::information(&newConnect, IPPort(IP, port) + " 连接失败", data);
}

void CCPSTest::toConnect(const QByteArray &IP, unsigned short port) {
    if (cm->isBind() > 0)
        cm->connectToHost(IP, port);
}

void CCPSTest::closeEvent(QCloseEvent *e) {
    if (cm != nullptr)cm->quit();
    cm = nullptr;
    newConnect.close();
    if (setCert != nullptr)setCert->deleteLater();
    setCert = nullptr;
    QWidget::closeEvent(e);
}
