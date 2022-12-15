//
// Created by chenenyu on 2017/3/15.
//

#include <jni.h>

#ifndef ANDROIDSECURITY_NATIVE_SECURITY_H
#define ANDROIDSECURITY_NATIVE_SECURITY_H

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jstring JNICALL
Java_com_chenenyu_security_Security_getSecret(JNIEnv *env, jclass type);

// 获取当前应用的签名
//JNIEXPORT jchar JNICALL
//Java_com_chenenyu_security_Security_getSign(JNIEnv *env, jclass type);

// jstring转为char*
char *jstring2cStr(JNIEnv *env, jstring jstr);

// char*转为jstring
jstring cStr2jstring(JNIEnv *env, const char *pat);

// long转为char
char *jlong2char(JNIEnv *env, jlong number);

// char转为16进制
char *char2Hex(unsigned char c, char* hexValue) ;

#ifdef __cplusplus
}
#endif

#endif //ANDROIDSECURITY_NATIVE_SECURITY_H
