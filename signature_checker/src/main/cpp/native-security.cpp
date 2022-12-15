#include <android/log.h>
#include <string>
#include "native-security.h"

#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "security", __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, "security", __VA_ARGS__))
//https://blog.mikepenz.dev/a/protect-secrets-p3/
//https://www.cnblogs.com/bwlcool/p/8580206.html
//FIXME Why get SIGN from Cmake build pass Args ?
static const char *SIGN = "308203653082024da003020102020442e399f9300d06092a864886f70d01010"
                          "b05003062310b3009060355040613023836310b300906035504081302434e3110300e060355040713"
                          "074265696a696e67310f300d060355040a130662797465616d310f300d060355040b1306627974656"
                          "16d31123010060355040313094368656e20456e79753020170d3137303331363033313034315a180f"
                          "32313136303232313033313034315a3062310b3009060355040613023836310b30090603550408130"
                          "2434e3110300e060355040713074265696a696e67310f300d060355040a130662797465616d310f30"
                          "0d060355040b130662797465616d31123010060355040313094368656e20456e797530820122300d0"
                          "6092a864886f70d01010105000382010f003082010a0282010100a82303afa4c0a66c381679f5e9be"
                          "2f3f5142d82c47f2e40ef4bc23eaa511c48a01514a356679c9b0d5365f5c4d283abcb96e4a3afa2e3"
                          "e612400aea74be35e0251a99ccc3ee0db4dcb4714dbc57466eb0dd097a07f05364f99eb81a8196562"
                          "f88e95b48be19203f2acedda9dfc68150671c94957717d2c5de758fa3809d3de1c6f264d24ae336b9"
                          "0a4fb873618fb3b9b4e53dced1b4f657ba85375f9f57a674cf327ecdc405ae4796fdae0100874ea5c"
                          "226e8cf70150f19e40e61b9321cf4e407f5c9bd4410d5372dd21b759297b1d2e1bc3df624919ce5b0"
                          "0c67512c5db0a480bfe0a6ad462f5c5f6cf4c45e3281988d8fdfd913d0c0e1ca4c702f2a8c191f902"
                          "03010001a321301f301d0603551d0e04160414cf850a52b04103f63285964fd6dad179aabf9300300"
                          "d06092a864886f70d01010b050003820101008c409146564b1a34ef49e61ecbc2da7db32d3b9e1c58"
                          "15b1e2ba7eaba21dc0b5676aed0742450e3056489de4b6f3ad2b088f0038d32d3ed3ab7680de3fd7f"
                          "d09abe4e426dbb0929e220a985356c38b6bb22b2f44dc9543391f0dbe49c5ec9c604de9a7de2e6ba0"
                          "99c6cca0c5b098a069d53a55af0515cc0183bf81c733442dcff4fdea74f50e8870a1a579784dee29a"
                          "97be59ab5098eaa73c5c4e43aa3b13f9382dbf6473b8fddb40958b2fe6696e8a5bc3ac53ec78f20b9"
                          "bf212c6aeba3af4351771ca31bec26dc5424fc1cc7d129ba671165d0a600f0a2773708ef1596db795"
                          "2e852dd1313f02baa97d92af073844ba1c57a2e3cadefdc841af7592462b65a";

static const char *PROD_SIGN_SHA1 = "0D:62:00:54:B9:FF:42:9F:74:E3:5F:4B:F7:06:87:6E:70:0A:A8:D3";

#define HEX_VALUES "0123456789ABCDEF"

static int verifySign(JNIEnv *env);
static int verifySignSHA(JNIEnv *env,char *type) ;

char *getDefaultSign() {
    int len = strlen(SIGN);
    char *defaultSign = (char *) malloc(len + 1);
    strcpy(defaultSign, SIGN);
    return defaultSign;
}

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_4) != JNI_OK) {
        return JNI_ERR;
    }
//    if (verifySign(env) == JNI_OK) {
        if (verifySignSHA(env,"SHA-1") == JNI_OK) {
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

jstring getFlavor(JNIEnv *env) {
    jstring flavor = NULL;
    jobject application = getApplication(env);
    if (application == NULL) {
        return flavor;
    }
    jclass context_clz = env->GetObjectClass(application);
    jmethodID getPackageManager = env->GetMethodID(context_clz, "getPackageManager",
                                                   "()Landroid/content/pm/PackageManager;");
    jobject package_manager = env->CallObjectMethod(application, getPackageManager);
    jclass package_manager_clz = env->GetObjectClass(package_manager);
    jmethodID getPackageInfo = env->GetMethodID(package_manager_clz, "getPackageInfo",
                                                "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    jmethodID getPackageName = env->GetMethodID(context_clz, "getPackageName",
                                                "()Ljava/lang/String;");
    jstring package_name = (jstring) (env->CallObjectMethod(application, getPackageName));
    const char *name_str_c = env->GetStringUTFChars(package_name, NULL);
    std::string name_str = name_str_c;
    name_str += ".BuildConfig";
    std::replace(name_str.begin(), name_str.end(), '.', '/');
    jclass cls_BuildConfig = env->FindClass(name_str.c_str());
    jfieldID fid_BuildConfig_flavor = env->GetStaticFieldID(cls_BuildConfig, "FLAVOR",
                                                            "Ljava/lang/String;");
    flavor = (jstring) env->GetStaticObjectField(cls_BuildConfig, fid_BuildConfig_flavor);
    return flavor;
}

jstring getBuildType(JNIEnv *env) {
    jstring buildtype = NULL;
    jobject application = getApplication(env);
    if (application == NULL) {
        return buildtype;
    }
    jclass context_clz = env->GetObjectClass(application);
    jmethodID getPackageManager = env->GetMethodID(context_clz, "getPackageManager",
                                                   "()Landroid/content/pm/PackageManager;");
    jobject package_manager = env->CallObjectMethod(application, getPackageManager);
    jclass package_manager_clz = env->GetObjectClass(package_manager);
    jmethodID getPackageInfo = env->GetMethodID(package_manager_clz, "getPackageInfo",
                                                "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    jmethodID getPackageName = env->GetMethodID(context_clz, "getPackageName",
                                                "()Ljava/lang/String;");
    jstring package_name = (jstring) (env->CallObjectMethod(application, getPackageName));
    const char *name_str_c = env->GetStringUTFChars(package_name, NULL);
    std::string name_str = name_str_c;
    name_str += ".BuildConfig";
    std::replace(name_str.begin(), name_str.end(), '.', '/');
    jclass cls_BuildConfig = env->FindClass(name_str.c_str());
    jfieldID fid_BuildConfig_buildType = env->GetStaticFieldID(cls_BuildConfig, "BUILD_TYPE",
                                                               "Ljava/lang/String;");
    buildtype = (jstring) env->GetStaticObjectField(cls_BuildConfig, fid_BuildConfig_buildType);
    return buildtype;
}

static int verifySign(JNIEnv *env) {
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
    LOGE("Show Application  package_name ：%s", name_str.c_str());
    name_str += ".BuildConfig";
    std::replace(name_str.begin(), name_str.end(), '.', '/');
    LOGE("Show Application  BuildConfig ：%s", name_str.c_str());
    //FIXME Here we can get BuildConfig --> flavor+buildtype -- we need replace . to /
//    jclass cls_BuildConfig = env->FindClass("com/chenenyu/security/BuildConfig");
    jclass cls_BuildConfig = env->FindClass(name_str.c_str());
    jfieldID fid_BuildConfig_buildType = env->GetStaticFieldID(cls_BuildConfig, "BUILD_TYPE",
                                                               "Ljava/lang/String;");
    jfieldID fid_BuildConfig_flavor = env->GetStaticFieldID(cls_BuildConfig, "FLAVOR",
                                                            "Ljava/lang/String;");
    jfieldID fid_BuildConfig_isdebug = env->GetStaticFieldID(cls_BuildConfig, "DEBUG", "Z");
    jstring jBuildType = (jstring) env->GetStaticObjectField(cls_BuildConfig,
                                                             fid_BuildConfig_buildType);
    jstring jBuildFlavor = (jstring) env->GetStaticObjectField(cls_BuildConfig,
                                                               fid_BuildConfig_flavor);
    jboolean jIsDebug = env->GetStaticBooleanField(cls_BuildConfig, fid_BuildConfig_isdebug);
    const char *buildType = env->GetStringUTFChars(jBuildType, nullptr);
    const char *buildflavor = env->GetStringUTFChars(jBuildFlavor, nullptr);
    LOGE("Application buildflavor：%s", buildflavor);
    LOGE("Application buildType：%s", buildType);
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
                                                           env->NewStringUTF("SHA1"));

    // 获取MessageDigestObj.digest
    jmethodID MessageDigestClass_method_digest = env->GetMethodID(MessageDigestClass, "digest",
                                                                  "([B)[B");
    jobject publicKey = env->CallObjectMethod(MessageDigestObj, MessageDigestClass_method_digest,
                                              x509CertificateObj_encoded);
    jbyteArray publicKeyArr = reinterpret_cast<jbyteArray>(publicKey);
    LOGI("getSign convert to 0x");
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
    LOGE("应用中读取到的签名MessageDigest SHA1 为：%s", sign_key_type_sha);
    LOGI("应用中读取到的签名CharsString为：%s", sign);
    LOGI("native中预置的签名CharsString为：%s", SIGN);
//    int result = strcmp(sign, SIGN);
    int result = strcmp(sign_key_type_sha, PROD_SIGN_SHA1);
    // 使用之后要释放这段内存
    env->ReleaseStringUTFChars(signature_str, sign);
    env->DeleteLocalRef(signature_str);
    if (result == 0) { // 签名一致
        return JNI_OK;
    }

    return JNI_ERR;
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
    LOGE("Show Application  package_name ：%s", name_str.c_str());
    name_str += ".BuildConfig";
    std::replace(name_str.begin(), name_str.end(), '.', '/');
    LOGE("Show Application  BuildConfig ：%s", name_str.c_str());
    //FIXME Here we can get BuildConfig --> flavor+buildtype -- we need replace . to /
//    jclass cls_BuildConfig = env->FindClass("com/chenenyu/security/BuildConfig");
    jclass cls_BuildConfig = env->FindClass(name_str.c_str());
    jfieldID fid_BuildConfig_buildType = env->GetStaticFieldID(cls_BuildConfig, "BUILD_TYPE",
                                                               "Ljava/lang/String;");
    jfieldID fid_BuildConfig_flavor = env->GetStaticFieldID(cls_BuildConfig, "FLAVOR",
                                                            "Ljava/lang/String;");
    jfieldID fid_BuildConfig_isdebug = env->GetStaticFieldID(cls_BuildConfig, "DEBUG", "Z");
    jstring jBuildType = (jstring) env->GetStaticObjectField(cls_BuildConfig,
                                                             fid_BuildConfig_buildType);
    jstring jBuildFlavor = (jstring) env->GetStaticObjectField(cls_BuildConfig,
                                                               fid_BuildConfig_flavor);
    jboolean jIsDebug = env->GetStaticBooleanField(cls_BuildConfig, fid_BuildConfig_isdebug);
    const char *buildType = env->GetStringUTFChars(jBuildType, nullptr);
    const char *buildflavor = env->GetStringUTFChars(jBuildFlavor, nullptr);
    LOGE("Application buildflavor：%s", buildflavor);
    LOGE("Application buildType：%s", buildType);
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
    LOGI("getSign convert to 0x");
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
    LOGE("应用中读取到的签名MessageDigest SHA1 为：%s", sign_key_type_sha);
    LOGI("native中预置的签名MessageDigest SHA1 为：%s", PROD_SIGN_SHA1);
    int result = strcmp(sign_key_type_sha, PROD_SIGN_SHA1);
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
        LOGI("native中预置的签名为：%s", SIGN);
        result = strcmp(sign, SIGN);
    } else if (strcmp(flavor_build_type, "global") == 0) {
        LOGI("native中预置的签名为：%s", PROD_SIGN_SHA1);
        result = strcmp(sign, PROD_SIGN_SHA1);
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

const char *getSignature(JNIEnv *env) {
//jstring Java_com_chenenyu_security_Security_getSign(JNIEnv *env, jclass type) {
    LOGI("getSign start");
    jobject context = getApplication(env);
    if (context == NULL) {
        LOGI("getSign: not found context, return default value");
        return getDefaultSign();
    }
    jclass activity = env->GetObjectClass(context);
    // 得到 getPackageManager 方法的 ID
    jmethodID methodID_func = env->GetMethodID(activity, "getPackageManager",
                                               "()Landroid/content/pm/PackageManager;");
    // 获得PackageManager对象
    jobject packageManager = env->CallObjectMethod(context, methodID_func);
    jclass packageManagerclass = env->GetObjectClass(packageManager);
    //得到 getPackageName 方法的 ID
    jmethodID methodID_pack = env->GetMethodID(activity, "getPackageName", "()Ljava/lang/String;");
    //获取包名
    jstring name_str = static_cast<jstring>(env->CallObjectMethod(context, methodID_pack));
    const char *name_str_c = env->GetStringUTFChars(name_str, NULL);
    LOGE("Show 包名 ：%s", name_str_c);
    // 得到 getPackageInfo 方法的 ID
    jmethodID methodID_pm = env->GetMethodID(packageManagerclass, "getPackageInfo",
                                             "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    // 获得应用包的信息
    jobject package_info = env->CallObjectMethod(packageManager, methodID_pm, name_str, 64);
    // 获得 PackageInfo 类
    jclass package_infoclass = env->GetObjectClass(package_info);
    // 获得签名数组属性的 ID
    jfieldID fieldID_signatures = env->GetFieldID(package_infoclass, "signatures",
                                                  "[Landroid/content/pm/Signature;");
    // 得到签名数组，待修改
    jobject signatur = env->GetObjectField(package_info, fieldID_signatures);
    jobjectArray signatures = reinterpret_cast<jobjectArray>(signatur);
    // 得到签名
    jobject signature = env->GetObjectArrayElement(signatures, 0);
    // 获得 Signature 类，待修改
    jclass signature_clazz = env->GetObjectClass(signature);
    // 获取toByteArray方法ID
    jmethodID signature_method_toByteArray = env->GetMethodID(signature_clazz, "toByteArray",
                                                              "()[B");
    jobject signatureBytes = env->CallObjectMethod(signature, signature_method_toByteArray);
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
                                                           env->NewStringUTF("SHA1"));

    // 获取MessageDigestObj.digest
    jmethodID MessageDigestClass_method_digest = env->GetMethodID(MessageDigestClass, "digest",
                                                                  "([B)[B");
    jobject publicKey = env->CallObjectMethod(MessageDigestObj, MessageDigestClass_method_digest,
                                              x509CertificateObj_encoded);
    jbyteArray publicKeyArr = reinterpret_cast<jbyteArray>(publicKey);
    LOGI("getSign convert to 0x");
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

    LOGI("getSign finish");

    return sign_key_type_sha;
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