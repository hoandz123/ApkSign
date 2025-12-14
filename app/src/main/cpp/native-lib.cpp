#include <jni.h>
#include <string>
#include <android/log.h>
#include "apksig/apksig.hpp"

#define LOG_TAG "ApkSign"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {
    std::string escapeJsonString(const std::string& str) {
        std::string escaped;
        escaped.reserve(str.length() + 10);
        for (char c : str) {
            switch (c) {
                case '"': escaped += "\\\""; break;
                case '\\': escaped += "\\\\"; break;
                case '\n': escaped += "\\n"; break;
                case '\r': escaped += "\\r"; break;
                case '\t': escaped += "\\t"; break;
                default: escaped += c; break;
            }
        }
        return escaped;
    }
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_hmg_apksign_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "APK Signature Verification Library - Ready";
    return env->NewStringUTF(hello.c_str());
}

/**
 * Verify APK signature from file path
 * @param env JNI environment
 * @param thiz Java object
 * @param apkPath Path to APK file
 * @return JSON string with verification result
 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_hmg_apksign_MainActivity_verifyApkSignature(
        JNIEnv* env,
        jobject /* thiz */,
        jstring apkPath) {
    if (!apkPath) {
        return env->NewStringUTF("{\"success\":false,\"error\":\"APK path is null\"}");
    }
    
    const char* pathStr = env->GetStringUTFChars(apkPath, nullptr);
    if (!pathStr) {
        return env->NewStringUTF("{\"success\":false,\"error\":\"Failed to get APK path\"}");
    }
    
    std::string apkPathStr(pathStr);
    env->ReleaseStringUTFChars(apkPath, pathStr);
    
    LOGI("Verifying APK signature: %s", apkPathStr.c_str());
    
    try {
        apksig::VerificationResult result = apksig::ApkVerifier::verify(apkPathStr);
        
        std::string json = "{";
        json += "\"success\":" + std::string(result.success ? "true" : "false") + ",";
        json += "\"error_message\":\"" + escapeJsonString(result.error_message) + "\",";
        json += "\"signature_blocks_count\":" + std::to_string(result.signature_blocks.size()) + ",";
        json += "\"certificates_count\":" + std::to_string(result.certificates.size());
        
        if (!result.certificates.empty()) {
            json += ",\"first_certificate_base64\":\"";
            json += apksig::CertificateExtractor::encodeCertificateBase64(result.certificates[0]);
            json += "\"";
        }
        
        json += "}";
        
        LOGI("Verification result: success=%d, blocks=%zu, certs=%zu",
             result.success, result.signature_blocks.size(), result.certificates.size());
        
        return env->NewStringUTF(json.c_str());
        
    } catch (const std::exception& e) {
        LOGE("Exception during verification: %s", e.what());
        std::string errorJson = "{\"success\":false,\"error\":\"" + escapeJsonString(e.what()) + "\"}";
        return env->NewStringUTF(errorJson.c_str());
    } catch (...) {
        LOGE("Unknown exception during verification");
        return env->NewStringUTF("{\"success\":false,\"error\":\"Unknown exception\"}");
    }
}

/**
 * Get certificate from APK as base64 string
 * @param env JNI environment
 * @param thiz Java object
 * @param apkPath Path to APK file
 * @return Base64-encoded certificate string, or empty string on error
 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_hmg_apksign_MainActivity_getCertificateBase64(
        JNIEnv* env,
        jobject /* thiz */,
        jstring apkPath) {
    if (!apkPath) {
        return env->NewStringUTF("");
    }
    
    const char* pathStr = env->GetStringUTFChars(apkPath, nullptr);
    if (!pathStr) {
        return env->NewStringUTF("");
    }
    
    std::string apkPathStr(pathStr);
    env->ReleaseStringUTFChars(apkPath, pathStr);
    
    LOGI("Getting certificate from APK: %s", apkPathStr.c_str());
    
    try {
        std::string certBase64 = apksig::ApkVerifier::getCertificateBase64(apkPathStr);
        return env->NewStringUTF(certBase64.c_str());
    } catch (const std::exception& e) {
        LOGE("Exception getting certificate: %s", e.what());
        return env->NewStringUTF("");
    } catch (...) {
        LOGE("Unknown exception getting certificate");
        return env->NewStringUTF("");
    }
}