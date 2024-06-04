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
#define CUCP const unsigned char *
#define UCP unsigned char *

KEY_DLL int GenKeyPair(UCP priKey, UCP pubKey);
KEY_DLL int GetPubKey(CUCP priKey, UCP pubKey);
KEY_DLL int GenSharedKey(CUCP priKey, CUCP pubKey, UCP sharedKey);
KEY_DLL int EncryptData(CUCP msg, int msgSize, CUCP key, CUCP IV, UCP cipher); // 加密
KEY_DLL int DecryptData(CUCP cipher, int cipherSize, CUCP key, CUCP IV, UCP msg); // 解密
KEY_DLL int Verify(CUCP pubKey, CUCP msg, int msgSize, CUCP sign, int signSize);
KEY_DLL void Rand(UCP data, int size);
KEY_DLL int Sha512(CUCP msg, int msgSize, UCP sha512);

#endif
