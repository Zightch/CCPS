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
KEY_DLL int GetPubKey(unsigned char *priKey, unsigned char *pubKey);
KEY_DLL int GenSharedKey(unsigned char *priKey, unsigned char *pubKey, unsigned char *sharedKey);
KEY_DLL int EncryptData(unsigned char *msg, int msgSize, unsigned char *key, unsigned char *IV, unsigned char *cipher);
KEY_DLL int DecryptData(unsigned char *cipher, int cipherSize, unsigned char *key, unsigned char *IV, unsigned char *msg);
KEY_DLL int Verify(unsigned char *pubKey, unsigned char *msg, long long msgSize, unsigned char *sign, long long signSize);

#endif
