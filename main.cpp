#include "CFUPSTest/CFUPSTest.h"

#include <QApplication>

int main(int argc, char *argv[]) {
    QApplication a(argc, argv);
    CFUPSTest w;
    w.show();
    return QApplication::exec();
}
