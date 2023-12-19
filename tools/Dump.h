#pragma once

class Dump {
public:
    Dump(Dump &&) = delete;

    Dump &&operator=(Dump &&) = delete;

    Dump();

    ~Dump();

    Dump &push(char);

    Dump &push(short);

    Dump &push(int);

    Dump &push(long long);

    Dump &push(unsigned char);

    Dump &push(unsigned short);

    Dump &push(unsigned int);

    Dump &push(unsigned long long);

    Dump &push(float);

    Dump &push(double);

    Dump &push(const char *, unsigned long long);

    Dump &push(const char *);

    Dump &clear();

    [[nodiscard]]
    char *get() const;

    [[nodiscard]]
    unsigned long long size() const;

private:
    void joint(const char *, unsigned long long);

    char *buff = nullptr;
    unsigned long long size_ = 0;
};
