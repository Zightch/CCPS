#pragma once

#include <functional>

template<class T>
class Trie {
public:
    Trie(const Trie &) = delete;

    Trie &operator=(const Trie &) = delete;

    Trie();

    ~Trie();

    void insert(const char *, const T &);

    T &find(const char *);

    void remove(const char *);

    void clear();

    bool exist(const char *);

    unsigned long long size();

    void traverse(std::function<void(T &, const char *)>, const char * = "");

    T &operator[](const char *);

private:

    void traverse_(std::function<void(T &, const char *)>, const char * = "");

    Trie<T> *parent = nullptr;
    Trie<T> **subPoint = nullptr;
    T *t = nullptr;
};

template<class T>
Trie<T>::Trie() {
    subPoint = new Trie<T> *[256];
    for (unsigned short i = 0; i < 256; i++)
        subPoint[i] = nullptr;
}

template<class T>
Trie<T>::~Trie() {
    clear();
    delete[]subPoint;
    subPoint = nullptr;
    delete t;
    t = nullptr;
}

template<class T>
void Trie<T>::insert(const char *key, const T& item) {
    if (key == nullptr) throw "Trie<T>::insert : key不能为空";
    Trie<T> *currentPoint = this;
    unsigned long long i = 0;
    while (key[i] != 0) {
        unsigned char tmp = key[i] + 128;
        if (key[i + 1] == 0) {
            if (currentPoint->subPoint[tmp] == nullptr) {
                currentPoint->subPoint[tmp] = new Trie<T>;
                currentPoint->subPoint[tmp]->parent = currentPoint;
                currentPoint = currentPoint->subPoint[tmp];
                if (currentPoint->t == nullptr)
                    currentPoint->t = new T;
                (*currentPoint->t) = item;
                return;
            } else {
                currentPoint = currentPoint->subPoint[tmp];
                if (currentPoint->t == nullptr)
                    currentPoint->t = new T;
                (*currentPoint->t) = item;
                return;
            }
        } else if (currentPoint->subPoint[tmp] == nullptr) {
            currentPoint->subPoint[tmp] = new Trie<T>;
            currentPoint->subPoint[tmp]->parent = currentPoint;
            currentPoint = currentPoint->subPoint[tmp];
        } else
            currentPoint = currentPoint->subPoint[tmp];
        i++;
    }
    if (i == 0)
        throw "Trie<T>::insert : key不能为空";
    else
        throw "Trie<T>::insert : 发生未知错误";
}

template<class T>
T &Trie<T>::find(const char *key) {
    if (key == nullptr) throw "Trie<T>::find : key不能为空";
    Trie<T> *currentPoint = this;
    unsigned long long i = 0;
    while (key[i] != 0) {
        unsigned char tmp = key[i] + 128;
        if (key[i + 1] == 0) {
            if (currentPoint->subPoint[tmp] != nullptr) {
                currentPoint = currentPoint->subPoint[tmp];
                if (currentPoint->t != nullptr)
                    return (*currentPoint->t);
                else
                    throw "Trie<T>::find : 元素未找到";
            } else
                throw "Trie<T>::find : 元素未找到";
        } else if (currentPoint->subPoint[tmp] != nullptr)
            currentPoint = currentPoint->subPoint[tmp];
        else
            throw "Trie<T>::find : 元素未找到";
        i++;
    }
    if (i == 0)
        throw "Trie<T>::find : key不能为空";
    else
        throw "Trie<T>::find : 发生未知错误";
}

template<class T>
void Trie<T>::remove(const char *key) {
    if (key == nullptr) throw "Trie<T>::remove : key不能为空";
    Trie<T> *currentPoint = this;
    unsigned long long i = 0;
    while (key[i] != 0) {
        unsigned char tmp = key[i] + 128;
        if (key[i + 1] == 0) {
            if (currentPoint->subPoint[tmp] != nullptr) {
                currentPoint = currentPoint->subPoint[tmp];
                if (currentPoint->t != nullptr) {
                    delete currentPoint->t;
                    currentPoint->t = nullptr;
                }
                while (currentPoint->size() == 0) {
                    currentPoint = currentPoint->parent;
                    delete currentPoint->subPoint[tmp];
                    currentPoint->subPoint[tmp] = nullptr;
                    i--;
                    tmp = key[i] + 128;
                    if (i + 1 == 0)
                        break;
                }
                return;
            } else return;
        } else if (currentPoint->subPoint[tmp] != nullptr)
            currentPoint = currentPoint->subPoint[tmp];
        else return;
        i++;
    }
    if (i == 0)
        throw "Trie<T>::remove : key不能为空";
    else
        throw "Trie<T>::remove : 发生未知错误";
}

template<class T>
void Trie<T>::clear() {
    for (unsigned short i = 0; i < 256; i++) {
        if (subPoint[i] != nullptr) {
            delete subPoint[i];
            subPoint[i] = nullptr;
        }
    }
}

template<class T>
bool Trie<T>::exist(const char * key) {
    if (key == nullptr) throw "Trie<T>::exist : key不能为空";
    Trie<T> *currentPoint = this;
    unsigned long long i = 0;
    while (key[i] != 0) {
        unsigned char tmp = key[i] + 128;
        if (key[i + 1] == 0) {
            if (currentPoint->subPoint[tmp] != nullptr) {
                currentPoint = currentPoint->subPoint[tmp];
                return (currentPoint->t != nullptr);
            } else
                return false;
        } else if (currentPoint->subPoint[tmp] != nullptr)
            currentPoint = currentPoint->subPoint[tmp];
        else return false;
        i++;
    }
    if (i == 0)
        throw "Trie<T>::exist : key不能为空";
    else
        throw "Trie<T>::exist : 发生未知错误";
}

template<class T>
unsigned long long Trie<T>::size() {
    unsigned long long tmp = 0;
    if (t !=nullptr)tmp++;
    for (unsigned short i = 0; i < 256; i++)
        if (subPoint[i] != nullptr)
            tmp += subPoint[i]->size();
    return tmp;
}

template<class T>
void Trie<T>::traverse(std::function<void(T &, const char *)> callBack, const char* prefix) {
    if (prefix == nullptr) throw "Trie<T>::traverse : prefix不能为nullptr";
    if (callBack != nullptr) {
        Trie<T> *currentPoint = this;
        unsigned long long i = 0;
        while (prefix[i] != 0) {
            unsigned char tmp = prefix[i] + 128;
            if (currentPoint->subPoint[tmp] != nullptr) {
                currentPoint = currentPoint->subPoint[tmp];
                if (prefix[i + 1] == 0)break;
            } else
                throw "Trie<T>::traverse : 节点未找到";
            i++;
        }
        currentPoint->traverse_(callBack, prefix);
    }
}

template<class T>
T &Trie<T>::operator[](const char *key) {
    if (exist(key))
        return find(key);
    else {
        insert(key, T());
        return find(key);
    }
}

template<class T>
void Trie<T>::traverse_(std::function<void(T &, const char *)> callBack, const char *prefix) {
    if (t != nullptr)
        callBack(*t, prefix);
    for (unsigned short i = 0; i < 256; i++)
        if (subPoint[i] != nullptr) {
            unsigned long long len = 0;
            while (prefix[len++]);
            char *tmp = new char[++len];
            for (unsigned long long j = 0; j < len - 1; j++)
                tmp[j] = prefix[j];
            tmp[len - 2] = (char) (i - 128);
            tmp[len - 1] = 0;
            subPoint[i]->traverse_(callBack, tmp);
            delete[]tmp;
        }
}
