LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := key
LOCAL_SRC_FILES := key.c
LOCAL_CFLAGS    := -std=c17 -Wall
LOCAL_LDLIBS    := -lcrypto

include $(BUILD_SHARED_LIBRARY)
