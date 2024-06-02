#include "CCPSTest/CCPSTest.h"

#include <QApplication>

int main(int argc, char *argv[]) {
    QApplication a(argc, argv);
    CCPSTest w;
    w.show();
    return QApplication::exec();
}
