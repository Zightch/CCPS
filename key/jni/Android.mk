LOCAL_PATH := $(call my-dir)
OPENSSL_ROOT_PATH := E:/OpenSSL_Android

include $(CLEAR_VARS)

LOCAL_MODULE := openssl_crypto
LOCAL_SRC_FILES := $(OPENSSL_ROOT_PATH)/lib/libcrypto.a
LOCAL_EXPORT_C_INCLUDES := $(OPENSSL_ROOT_PATH)/include
LOCAL_EXPORT_LDLIBS := $(OPENSSL_ROOT_PATH)/lib/libcrypto.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_MODULE           := key
LOCAL_SRC_FILES        := key.c
LOCAL_CFLAGS           := -std=c17 -Wall -D__ANDROID_API__=22
LOCAL_STATIC_LIBRARIES := openssl_crypto
LOCAL_C_INCLUDES       := $(OPENSSL_ROOT_PATH)/include

include $(BUILD_SHARED_LIBRARY)
