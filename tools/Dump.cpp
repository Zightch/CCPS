#include "Dump.h"

Dump::Dump() {
    buff = new char[1];
    buff[0] = 0;
}

Dump::~Dump() {
    delete[]buff;
}

Dump& Dump::push(char c) {
    joint((char *) &c, 1);
    return *this;
}

Dump& Dump::push(short s) {
    joint((char *) &s, 2);
    return *this;
}

Dump& Dump::push(int d) {
    joint((char *) &d, 4);
    return *this;
}

Dump& Dump::push(long long ll) {
    joint((char *) &ll, 8);
    return *this;
}

void Dump::joint(const char *c, unsigned long long l) {
    char *tmp = buff;
    size_ += l;
    buff = new char[size_];
    for (unsigned long long i = 0; i < size_ - l; i++)
        buff[i] = tmp[i];
    delete[]tmp;
    for (unsigned long long i = size_ - l, j = 0; i < size_; i++, j++)
        buff[i] = c[j];
}

Dump& Dump::push(unsigned char uc) {
    joint((char *) &uc, 1);
    return *this;
}

char *Dump::get() const {
    return buff;
}

Dump& Dump::push(unsigned short us) {
    joint((char *) &us, 2);
    return *this;
}

Dump& Dump::push(unsigned int ui) {
    joint((char *) &ui, 4);
    return *this;
}

Dump& Dump::push(unsigned long long ull) {
    joint((char *) &ull, 8);
    return *this;
}

Dump& Dump::push(float f) {
    joint((char *) &f, 4);
    return *this;
}

Dump& Dump::push(double d) {
    joint((char *) &d, 8);
    return *this;
}

Dump& Dump::push(const char *cc, unsigned long long len) {
    joint(cc, len);
    return *this;
}

Dump& Dump::push(const char *cc) {
    unsigned long long len = 0;
    while (cc[len++]);
    len--;
    joint(cc, len);
    return *this;
}

unsigned long long Dump::size() const {
    return size_;
}

Dump &Dump::clear() {
    delete buff;
    buff = new char[1];
    buff[0] = 0;
    size_ = 0;
    return *this;
}
