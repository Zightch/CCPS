#ifndef KEY_H
#define KEY_H

#ifdef __cplusplus
#define C_IDENTIFY extern "C"
#else
#define C_IDENTIFY
#endif

#ifdef _WIN32
#ifdef EXPORT
#define KEY_DLL C_IDENTIFY __declspec(dllexport)
#else
#define KEY_DLL C_IDENTIFY __declspec(dllimport)
#endif
#elif __linux__
#define KEY_DLL C_IDENTIFY
#endif

#define LEN_25519 32
#define IV_LEN 16

KEY_DLL int GenKeyPair(unsigned char *priKey, unsigned char *pubKey);
KEY_DLL int GetPubKey(const unsigned char *priKey, unsigned char *pubKey);
KEY_DLL int GenSharedKey(const unsigned char *priKey, const unsigned char *pubKey, unsigned char *sharedKey);
KEY_DLL int EncryptData(const unsigned char *msg, int msgSize, const unsigned char *key, const unsigned char *IV, unsigned char *cipher);
KEY_DLL int DecryptData(const unsigned char *cipher, int cipherSize, const unsigned char *key, const unsigned char *IV, unsigned char *msg);
KEY_DLL int Verify(const unsigned char *pubKey, const unsigned char *msg, int msgSize, const unsigned char *sign, int signSize);
KEY_DLL void Rand(unsigned char *data, int size);
KEY_DLL int Sha512(const unsigned char *msg, int msgSize, unsigned char *sha512);

#endif
