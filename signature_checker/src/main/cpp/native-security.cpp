#include <jni.h>
#include <string>
#include <android/log.h>
#include <map>
#include <sstream>
#include <stdio.h>
#include "native-security.h"
#include <unordered_map>
#include "base64.h"

#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "security", __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, "security", __VA_ARGS__))
//https://blog.piasy.com/2017/08/26/Verify-App-Signature-and-JNI-Error-Handling/index.html
//https://blog.mikepenz.dev/a/protect-secrets-p3/
//https://www.cnblogs.com/bwlcool/p/8580206.html


#ifdef ISALT
const char* CSALT = ISALT;
#endif

#ifdef ITYPE
#endif

#ifdef ISHA
#endif

#ifdef FLAVOR_SHAS
#endif

#define HEX_VALUES "0123456789ABCDEF"

static std::string application_namespace;

std::string prepareApplicationNameSpace() {
    std::string package;
#ifdef JAVA_BUILDCONFIG_PACKAGE
    package = JAVA_BUILDCONFIG_PACKAGE;
#endif
    return package;
}

static std::string buildconfig;

static jclass BuildConfig;

std::string prepareApplicationBuildConfig() {
    if (application_namespace.empty()) {
        application_namespace = prepareApplicationNameSpace();
    }
    std::string item = application_namespace;
    item += ".BuildConfig";
    std::replace(item.begin(), item.end(), '.', '/');
    return item;
}

static const char *buildtype = nullptr;
static const char *buildflavor = nullptr;
static std::string flavorBuildType;
std::unordered_map <std::string, std::string> AllSHAs;

static int verifySignSHA(JNIEnv *env, char *type);

std::unordered_map <std::string, std::string> prepareSHA() {
    std::unordered_map <std::string, std::string> keys;
#ifdef FLAVOR_SHAS
//    LOGE("run prepareSHA " );
    std::string decoded_BASE64_VALUES = base64_decode(FLAVOR_SHAS);
//    LOGE("Show  base64_decode  VALUES  : %s\n", decoded_BASE64_VALUES.c_str());
    //// 使用 stringstream 和 getline 函数解析字符串
    //TODO Note : split "\t" & "=" if change at gradle , here must change
    std::stringstream ss(decoded_BASE64_VALUES);
    std::string item;
    while (std::getline(ss, item, '\t')) {
        std::size_t pos = item.find('=');
        std::string key = item.substr(0, pos);
        std::string value = item.substr(pos+1);
        keys[key] = value;
    }
#endif
    return keys;
}

void showAllSHA() {
    for (const auto &kv: AllSHAs) {
        LOGE("Show  %s  with  SHA：%2s", kv.first.c_str(), kv.second.c_str());
    }
}

const char *matchSHAByFlavorBuildType(const char *flavorBuildType) {
    // 使用 find 函数查找 map 中的键
    auto it = AllSHAs.find(flavorBuildType);
    if (it != AllSHAs.end()) {
        // 如果找到了键，返回对应的值
        return it->second.c_str();
    } else {
        // 如果没有找到键，返回空字符数组
        return "";
    }
}

// 定义一个名为 getJavaStringField 的函数，用于获取 Java 类中的字符串字段
const char *getJavaStringField(JNIEnv *env, jclass cls, const char *fieldName) {
    // 获取字符串字段的字段 ID
    jfieldID fieldId = env->GetStaticFieldID(cls, fieldName, "Ljava/lang/String;");
    // 检查是否发生异常
    if (env->ExceptionCheck()) {
        // 清除异常
        env->ExceptionClear();
        // 如果发生异常，则返回空指针
        return nullptr;
    }
    // 获取字符串字段的值
    jstring
    jstr = (jstring)
    env->GetObjectField(cls, fieldId);
    // 将字符串字段的值转换为 char*
    const char *str = env->GetStringUTFChars(jstr, nullptr);
    // 返回 char*
    return str;
}

char *jstring2cStr(JNIEnv *env, jstring jstr) {
    const char *temp = (char *) env->GetStringUTFChars(jstr, NULL);
    char *ret = (char *) malloc(strlen(temp) + 1);
    strcpy(ret, temp);
    env->ReleaseStringUTFChars(jstr, temp);
    return ret;
}

jstring cStr2jstring(JNIEnv *env, const char *chars) {
    jstring ret = env->NewStringUTF(chars);
    return ret;
}

char *jlong2char(JNIEnv *env, jlong number) {
    char *chars = (char *) malloc(20);
    sprintf(chars, "%lld", number);
    return chars;
}

char *char2Hex(unsigned char c, char *hexValue) {
    if (c < 16) {
        hexValue[0] = HEX_VALUES[0];
        hexValue[1] = HEX_VALUES[c];
    } else {
        int l = c / 16;
        int r = c % 16;
        hexValue[0] = HEX_VALUES[l];
        hexValue[1] = HEX_VALUES[r];
    }
    hexValue[2] = 0;
    return hexValue;
}

jfieldID
GetStaticFieldID(JNIEnv *env, jclass cls, const char *field_name, const char *field_signature) {
    jfieldID field_id = env->GetStaticFieldID(cls, field_name, field_signature);
    if (env->ExceptionCheck()) {
        // 清除异常
        env->ExceptionClear();
        return nullptr;
    }
    return field_id;
}

const char *getBuildTypeVaule(JNIEnv *env) {
//    std::string name_str = initJavaBuildConfig();
//    name_str += ".BuildConfig";
//    std::replace(name_str.begin(), name_str.end(), '.', '/');
//    LOGI("Show Application  PackageName ：%s", name_str.c_str());
    if (buildconfig.empty()) {
        buildconfig=prepareApplicationBuildConfig();
    }
    LOGI("Show Application  PackageName ：%s", buildconfig.c_str());
//    jclass cls_BuildConfig = env->FindClass(name_str.c_str());
    if (BuildConfig == NULL) {
        BuildConfig = env->FindClass(buildconfig.c_str());
    }
    jclass cls_BuildConfig = BuildConfig;
    if (cls_BuildConfig == NULL) {
        LOGE("cannot get BuildConfig");
        return nullptr;
    }
    jfieldID fid_BuildConfig_buildType = env->GetStaticFieldID(cls_BuildConfig, "BUILD_TYPE",  "Ljava/lang/String;");
    jstring jBuildType = (jstring) env->GetStaticObjectField(cls_BuildConfig, fid_BuildConfig_buildType);
//    env->DeleteLocalRef(application);
//    env->DeleteLocalRef(context_clz);
//    env->DeleteLocalRef(package_manager);
//    env->DeleteLocalRef(package_manager_clz);
//    env->DeleteLocalRef(package_name);
//    env->DeleteLocalRef(cls_BuildConfig);
//    env->DeleteLocalRef(jBuildType);//FIXME Hoe release?
    return env->GetStringUTFChars(jBuildType, nullptr);
}

const char *getBuildflavorVaule(JNIEnv *env) {
//    std::string name_str = initJavaBuildConfig();
//    name_str += ".BuildConfig";
//    std::replace(name_str.begin(), name_str.end(), '.', '/');
//    LOGI("Show Application  PackageName ：%s", name_str.c_str());
    if (buildconfig.empty()) {
        buildconfig=prepareApplicationBuildConfig();
    }
    LOGI("Show Application  PackageName ：%s", buildconfig.c_str());
//    jclass cls_BuildConfig = env->FindClass(name_str.c_str());
    if (BuildConfig == NULL) {
        BuildConfig = env->FindClass(buildconfig.c_str());
    }
    jclass cls_BuildConfig = BuildConfig;
    if (cls_BuildConfig == NULL) {
        LOGE("cannot get BuildConfig");
        return nullptr;
    }
    jfieldID fid_BuildConfig_flavor = GetStaticFieldID(env, cls_BuildConfig, "FLAVOR","Ljava/lang/String;");
//    env->DeleteLocalRef(application);
//    env->DeleteLocalRef(context_clz);
//    env->DeleteLocalRef(package_manager);
//    env->DeleteLocalRef(package_manager_clz);
//    env->DeleteLocalRef(package_name);
//    env->DeleteLocalRef(cls_BuildConfig);
    if (fid_BuildConfig_flavor != nullptr) {
        jstring
        jBuildFlavor = (jstring)
        env->GetStaticObjectField(cls_BuildConfig, fid_BuildConfig_flavor);
//        env->DeleteLocalRef(jBuildFlavor);//FIXME Hoe release?
        return env->GetStringUTFChars(jBuildFlavor, nullptr);
    } else {
        return nullptr;
    }
}

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_4) != JNI_OK) {
        return JNI_ERR;
    }
    if (buildtype == nullptr) {
        LOGI("buildtype is null ");
        buildtype = getBuildTypeVaule(env);
    }
    LOGI("Show now buildtype is ：%s", buildtype);
    std::string buildType(buildtype);
    flavorBuildType = buildType;
    LOGI("Show init FlavorBuildType is ：%s", flavorBuildType.c_str());
    if (buildflavor == nullptr) {
        LOGI("flavor is null ");
        buildflavor = getBuildflavorVaule(env);
    }
    LOGI("Show now flavor is ：%s", buildflavor);
    if (buildflavor != nullptr) {
        std::transform(buildType.begin(), buildType.begin() + 1, buildType.begin(), ::toupper);
        std::string buildFlavor = buildflavor;
        flavorBuildType = buildFlavor + buildType;
    }
    LOGI("Show now FlavorBuildType is ：%s", flavorBuildType.c_str());
    if (AllSHAs.empty()) {
        AllSHAs = prepareSHA();
    }
//    showAllSHA();
    if (verifySignSHA(env, ITYPE) == JNI_OK) {
        return JNI_VERSION_1_4;
    }
    LOGE("签名不一致!");
    return JNI_ERR;
}

//https://www.cnblogs.com/bwlcool/p/8580206.html
static jobject getApplication(JNIEnv *env) {
    jobject application = NULL;
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz != NULL) {
        jmethodID currentApplication = env->GetStaticMethodID(
                activity_thread_clz, "currentApplication", "()Landroid/app/Application;");
        if (currentApplication != NULL) {
            application = env->CallStaticObjectMethod(activity_thread_clz, currentApplication);
        } else {
            LOGE("Cannot find method: currentApplication() in ActivityThread.");
        }
        env->DeleteLocalRef(activity_thread_clz);
    } else {
        LOGE("Cannot find class: android.app.ActivityThread");
    }
    return application;
}

static int verifySignSHA(JNIEnv *env, char *type) {
    // Application object
    jobject application = getApplication(env);
    if (application == NULL) {
        return JNI_ERR;
    }
    // Context(ContextWrapper) class
    jclass context_clz = env->GetObjectClass(application);
    // getPackageManager()  得到 getPackageManager 方法的 ID
    jmethodID getPackageManager = env->GetMethodID(context_clz, "getPackageManager",
                                                   "()Landroid/content/pm/PackageManager;");
    // android.content.pm.PackageManager object 获得PackageManager对象
    jobject package_manager = env->CallObjectMethod(application, getPackageManager);
    // PackageManager class
    jclass package_manager_clz = env->GetObjectClass(package_manager);
    // getPackageInfo() 得到 getPackageInfo 方法的 ID
    jmethodID getPackageInfo = env->GetMethodID(package_manager_clz, "getPackageInfo",
                                                "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    // context.getPackageName() 得到 getPackageName 方法的 ID
    jmethodID getPackageName = env->GetMethodID(context_clz, "getPackageName",
                                                "()Ljava/lang/String;");
    // call getPackageName() and cast from jobject to jstring 获取包名
    jstring package_name = (jstring)(env->CallObjectMethod(application, getPackageName));
    // PackageInfo object 获得应用包的信息
    jobject package_info = env->CallObjectMethod(package_manager, getPackageInfo, package_name, 64);
    // class PackageInfo 获得 PackageInfo 类
    jclass package_info_clz = env->GetObjectClass(package_info);
    // field signatures 获得签名数组属性的 ID
    jfieldID signatures_field = env->GetFieldID(package_info_clz, "signatures",
                                                "[Landroid/content/pm/Signature;");
    // 得到签名数组，待修改
    jobject signatures = env->GetObjectField(package_info, signatures_field);
    jobjectArray signatures_array = (jobjectArray) signatures;
    // 得到签名
    jobject signature0 = env->GetObjectArrayElement(signatures_array, 0);
    // 获得 Signature 类，待修改
    jclass signature_clz = env->GetObjectClass(signature0);
    // 获取toCharsString方法ID
    jmethodID toCharsString = env->GetMethodID(signature_clz, "toCharsString",
                                               "()Ljava/lang/String;");

    // 获取toByteArray方法ID
    jmethodID signature_method_toByteArray = env->GetMethodID(signature_clz, "toByteArray",
                                                              "()[B");
    // call toCharsString()
    jstring signature_str = (jstring)(env->CallObjectMethod(signature0, toCharsString));

    jobject signatureBytes = env->CallObjectMethod(signature0, signature_method_toByteArray);
    // 获取InputStream对象
    jclass inputStreamClass = env->FindClass("java/io/ByteArrayInputStream");
    jobject inputStreamObj = env->NewObject(
            inputStreamClass,
            env->GetMethodID(inputStreamClass, "<init>", "([B)V"),
            signatureBytes
    );
    // 获取CertificateFactory对象
    jclass certificateClass = env->FindClass("java/security/cert/CertificateFactory");
    jmethodID certificateClass_getInstance = env->GetStaticMethodID(certificateClass, "getInstance",
                                                                    "(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;");
    jobject certificateFactoryObj = env->CallStaticObjectMethod(certificateClass,
                                                                certificateClass_getInstance,
                                                                env->NewStringUTF("X509"));

    // 生成X509Certificate对象
    jmethodID certificateFactoryClass_method_generateCertificate = env->GetMethodID(
            certificateClass, "generateCertificate",
            "(Ljava/io/InputStream;)Ljava/security/cert/Certificate;");
    jobject x509CertificateObj = env->CallObjectMethod(certificateFactoryObj,
                                                       certificateFactoryClass_method_generateCertificate,
                                                       inputStreamObj);
    // 获取X509Certificate的c.getEncoded数据
    jmethodID X509Certificate_method_getEncoded = env->GetMethodID(
            env->FindClass("java/security/cert/Certificate"),
            "getEncoded", "()[B");
    jobject x509CertificateObj_encoded = env->CallObjectMethod(x509CertificateObj,
                                                               X509Certificate_method_getEncoded);
    // 生成MessageDigest
    jclass MessageDigestClass = env->FindClass("java/security/MessageDigest");
    jmethodID MessageDigestClass_getInstance = env->GetStaticMethodID(MessageDigestClass,
                                                                      "getInstance",
                                                                      "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jobject MessageDigestObj = env->CallStaticObjectMethod(MessageDigestClass,
                                                           MessageDigestClass_getInstance,
                                                           env->NewStringUTF(type));

    // 获取MessageDigestObj.digest
    jmethodID MessageDigestClass_method_digest = env->GetMethodID(MessageDigestClass, "digest",
                                                                  "([B)[B");
    jobject publicKey = env->CallObjectMethod(MessageDigestObj, MessageDigestClass_method_digest,
                                              x509CertificateObj_encoded);
    jbyteArray publicKeyArr = reinterpret_cast<jbyteArray>(publicKey);
    // 对获取的key进程16进制转换
    int length = env->GetArrayLength(publicKeyArr);
    jbyte *bytes = env->GetByteArrayElements(publicKeyArr, 0);
    char *sign_key_type_sha = (char *) malloc(length * 3);
    int sign_key_type_shaIndex = 0;
    char tempHex[3];
    for (int i = 0; i < length; i++) {
        char2Hex(bytes[i], tempHex);
        sign_key_type_sha[sign_key_type_shaIndex++] = tempHex[0];
        sign_key_type_sha[sign_key_type_shaIndex++] = tempHex[1];
        if (i < length - 1) {
            sign_key_type_sha[sign_key_type_shaIndex++] = ':';
        } else {
            sign_key_type_sha[sign_key_type_shaIndex++] = 0;
        }
    }

//    showAllSHA( );
    // release
    env->DeleteLocalRef(application);
    env->DeleteLocalRef(context_clz);
    env->DeleteLocalRef(package_manager);
    env->DeleteLocalRef(package_manager_clz);
    env->DeleteLocalRef(package_name);
    env->DeleteLocalRef(package_info);
    env->DeleteLocalRef(package_info_clz);
    env->DeleteLocalRef(signatures);
    env->DeleteLocalRef(signature0);
    env->DeleteLocalRef(signature_clz);

    const char *sign = env->GetStringUTFChars(signature_str, NULL);
    if (sign == NULL) {
        LOGE("分配内存失败");
        return JNI_ERR;
    }
    const char *match_sha = matchSHAByFlavorBuildType(flavorBuildType.c_str());
    //    LOGE("Show match ：%s", match_sha );
//    LOGI("应用中读取到的签名MessageDigest %s 为：%2s",ITYPE, sign_key_type_sha);
//    LOGI("native中预置的签名MessageDigest %s 为：%2s",ITYPE,  match_sha);
    int result = strcmp(sign_key_type_sha, match_sha);
    env->ReleaseStringUTFChars(signature_str, sign);
    env->DeleteLocalRef(signature_str);
    if (result == 0) { // 签名一致
        return JNI_OK;
    }

    return JNI_ERR;
}

jstring Java_com_chenenyu_security_Security_getSecret(JNIEnv *env, jclass type) {
    return env->NewStringUTF("Security str from native.");
}

//JNIEXPORT jstring JNICALL
//Java_com_chenenyu_security_Security_getSdkKey(JNIEnv *env, jclass type) {
//    return (*env)->NewStringUTF(env, "amazing-key");
//}
//
//JNIEXPORT jstring JNICALL
//Java_com_chenenyu_security_Security_getSdkSecret(JNIEnv *env, jclass type) {
//    // modify fingerprint to your certificates fingerprint here
//    if (strcmp("66C60BDAE163ECDB2A8871C0B53FFF00", getSignature(env )) == 0) {
//        char str[20];
//        const char *Z = "secret";
//        const char *X = "super-";
//        const char *Y = "secure-";
//        strcpy(str, X);
//        strcat(str, Y);
//        strcat(str, Z);
//        return (*env)->NewStringUTF(env, str);
//    } else {
//        return (*env)->NewStringUTF(env, "not-verified");
//    }
//}

