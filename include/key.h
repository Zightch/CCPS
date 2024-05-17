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

#define X25519_LEN 32
#define IV_LEN 16

KEY_DLL int genKeyPair(unsigned char *priKey, unsigned char *pubKey);
KEY_DLL int genSharedKey(unsigned char *priKey, unsigned char *pubKey, unsigned char *sharedKey);
KEY_DLL int encryptData(unsigned char *msg, int msgSize, unsigned char *key, unsigned char *IV, unsigned char *cipher);
KEY_DLL int decryptData(unsigned char *cipher, int cipherSize, unsigned char *key, unsigned char *IV, unsigned char *msg);

#endif
