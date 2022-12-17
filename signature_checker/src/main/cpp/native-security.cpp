#include <android/log.h>
#include <string>
#include "native-security.h"

#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "security", __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, "security", __VA_ARGS__))
//https://blog.mikepenz.dev/a/protect-secrets-p3/
//https://www.cnblogs.com/bwlcool/p/8580206.html
//FIXME Why get SIGN from Cmake build pass Args with flavor and module   ?
static const char *DEFAULT_SIGN = "0D:62:00:54:B9:FF:42:9F:74:E3:5F:4B:F7:06:87:6E:70:0A:A8:D3";

#ifdef ISALT
const char* CSALT = ISALT;

#endif

#ifdef ITYPE

#endif

#ifdef ISHA

#endif

#ifdef FLAVOR_SHAS
  std::cout << "FLAVOR_SHAS: " << FLAVOR_SHAS << std::endl;
#endif

#define HEX_VALUES "0123456789ABCDEF"

static int verifySignSHA(JNIEnv *env,char *type) ;

char *getDefaultSign() {
    int len = strlen(DEFAULT_SIGN);
    char *defaultSign = (char *) malloc(len + 1);
    strcpy(defaultSign, DEFAULT_SIGN);
    return defaultSign;
}

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_4) != JNI_OK) {
        return JNI_ERR;
    }

    if (verifySignSHA(env,ITYPE) == JNI_OK) {
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

static int verifySignSHA(JNIEnv *env,char *type) {
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
    jstring package_name = (jstring) (env->CallObjectMethod(application, getPackageName));
    const char *name_str_c = env->GetStringUTFChars(package_name, NULL);
    std::string name_str = name_str_c;
    LOGI("Show Application  PackageName ：%s", name_str.c_str());
    name_str += ".BuildConfig";
    std::replace(name_str.begin(), name_str.end(), '.', '/');
    jclass cls_BuildConfig = env->FindClass(name_str.c_str());
    if (cls_BuildConfig == nullptr) {
        // 没有找到类
        return -1;
    }
    jfieldID fid_BuildConfig_buildType = env->GetStaticFieldID(cls_BuildConfig, "BUILD_TYPE","Ljava/lang/String;");
    jstring jBuildType = (jstring) env->GetStaticObjectField(cls_BuildConfig,fid_BuildConfig_buildType);
    const char *buildType = env->GetStringUTFChars(jBuildType, nullptr);
    LOGI("Application BUILD_TYPE：%s", buildType);
    jfieldID fid_BuildConfig_isdebug = env->GetStaticFieldID(cls_BuildConfig, "DEBUG", "Z");
    jboolean jIsDebug = env->GetStaticBooleanField(cls_BuildConfig, fid_BuildConfig_isdebug);

    jfieldID fid_BuildConfig_flavor = GetStaticFieldID(env, cls_BuildConfig, "FLAVOR", "Ljava/lang/String;");
    if (fid_BuildConfig_flavor != nullptr) {
        jstring jBuildFlavor = (jstring) env->GetStaticObjectField(cls_BuildConfig,fid_BuildConfig_flavor);
        const char *buildflavor = env->GetStringUTFChars(jBuildFlavor, nullptr);
        LOGI("Application FLAVOR：%s", buildflavor);
    }

//    env->ReleaseStringUTFChars(jBuildType, buildType);//FIXME Release or del
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
    jstring signature_str = (jstring) (env->CallObjectMethod(signature0, toCharsString));

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
    LOGI("应用中读取到的签名MessageDigest %s 为：%2s",ITYPE, sign_key_type_sha);
//    LOGI("native中预置的签名MessageDigest %s 为：%2s",ITYPE,  ISHA);
    int result = strcmp(sign_key_type_sha, ISHA);
    env->ReleaseStringUTFChars(signature_str, sign);
    env->DeleteLocalRef(signature_str);
    if (result == 0) { // 签名一致
        return JNI_OK;
    }

    return JNI_ERR;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_chenenyu_security_Security_verifySignWithFlavorBuildType(JNIEnv *env, jobject thiz,
                                                                  jstring flavor_) {
    int result = JNI_ERR;//FIXME how set result type like : 0 = OK , -1 = Fail, -2= application is null, -3 = 分配内存失败  ,-4=verifySign fail
    // Application object
    jobject application = getApplication(env);
    if (application == NULL) {
        return result;
    }
    // Context(ContextWrapper) class
    jclass context_clz = env->GetObjectClass(application);
    // getPackageManager()
    jmethodID getPackageManager = env->GetMethodID(context_clz, "getPackageManager",
                                                   "()Landroid/content/pm/PackageManager;");
    // android.content.pm.PackageManager object
    jobject package_manager = env->CallObjectMethod(application, getPackageManager);
    // PackageManager class
    jclass package_manager_clz = env->GetObjectClass(package_manager);
    // getPackageInfo()
    jmethodID getPackageInfo = env->GetMethodID(package_manager_clz, "getPackageInfo",
                                                "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    // context.getPackageName()
    jmethodID getPackageName = env->GetMethodID(context_clz, "getPackageName",
                                                "()Ljava/lang/String;");
    // call getPackageName() and cast from jobject to jstring
    jstring package_name = (jstring) (env->CallObjectMethod(application, getPackageName));

    // PackageInfo object
    jobject package_info = env->CallObjectMethod(package_manager, getPackageInfo, package_name, 64);
    // class PackageInfo
    jclass package_info_clz = env->GetObjectClass(package_info);
//FIXME how get package_name ? then get BuildConfig ?
//    jclass cls_HelloJni = env->FindClass("com/example/hellojni/BuildConfig");
//    jfieldID fid_HelloJNI_buildType = env->GetStaticFieldID(cls_HelloJni, "BUILD_TYPE", "Ljava/lang/String;");
//    jstring jBuildType = (jstring) env->GetStaticObjectField(cls_HelloJni, fid_HelloJNI_buildType);
    // field signatures
    jfieldID signatures_field = env->GetFieldID(package_info_clz, "signatures",
                                                "[Landroid/content/pm/Signature;");
    jobject signatures = env->GetObjectField(package_info, signatures_field);
    jobjectArray signatures_array = (jobjectArray) signatures;
    jobject signature0 = env->GetObjectArrayElement(signatures_array, 0);
    jclass signature_clz = env->GetObjectClass(signature0);

    jmethodID toCharsString = env->GetMethodID(signature_clz, "toCharsString",
                                               "()Ljava/lang/String;");
    // call toCharsString()
    jstring signature_str = (jstring) (env->CallObjectMethod(signature0, toCharsString));

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
        result = JNI_ERR;
        return result;
    }

    const char *flavor_build_type = env->GetStringUTFChars(flavor_, 0);
    LOGI("应用中读取到的签名为：%s", sign);
//  if (result == 0)   // 签名一致
    if (strcmp(flavor_build_type, "bibigo") == 0) {
        LOGI("native中预置的签名为：%s", DEFAULT_SIGN);
        result = strcmp(sign, DEFAULT_SIGN);
    } else if (strcmp(flavor_build_type, "global") == 0) {
        LOGI("native中预置的签名为：%s", ISHA);
        result = strcmp(sign, ISHA);
    }

    // 使用之后要释放这段内存
    env->ReleaseStringUTFChars(signature_str, sign);
    env->DeleteLocalRef(signature_str);
    return result;
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

jfieldID GetStaticFieldID(JNIEnv* env, jclass cls, const char* field_name, const char* field_signature) {
    jfieldID field_id = env->GetStaticFieldID(cls, field_name, field_signature);
    if (env->ExceptionCheck()) {
        // 清除异常
        env->ExceptionClear();
        return nullptr;
    }
    return field_id;
}