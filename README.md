# APK Signature Verification Library - Dự án Mẫu

Dự án mẫu chuyên biệt cho thư viện **apksig** - thư viện C++ để xác minh chữ ký APK (v2/v3).

## Mô tả

Dự án này tích hợp thư viện `apksig` để xác minh chữ ký APK trên Android. Thư viện hỗ trợ:
- Xác minh chữ ký APK v2 và v3
- Trích xuất chứng chỉ X.509 từ APK
- Xác minh digest (SHA-256, SHA-512)
- Lấy chứng chỉ dưới dạng Base64

## Nguồn Tham Khảo

Thư viện apksig C++ trong dự án này được phát triển dựa trên:
- **[Android AOSP apksig](https://android.googlesource.com/platform/tools/apksig/)** - Thư viện Java chính thức của Android để xác minh và ký APK
- Thư viện AOSP hỗ trợ JAR signing và APK Signature Scheme v2/v3
- Dự án này là một port C++ của thư viện apksig Java để sử dụng trong Android NDK

## Cấu trúc Dự án

```
app/src/main/cpp/
├── CMakeLists.txt          # Cấu hình CMake
├── native-lib.cpp          # JNI bindings và ví dụ sử dụng
└── Includes/
    └── apksig/             # Thư viện apksig
        ├── apksig.hpp      # Header chính
        ├── apk_reader.hpp/cpp
        ├── apk_verifier.hpp/cpp
        ├── certificate_extractor.hpp/cpp
        ├── digest_verifier.hpp/cpp
        ├── signing_block_locator.hpp/cpp
        ├── signing_block_parser.hpp/cpp
        ├── signing_block.hpp
        ├── signature_scheme.hpp
        └── v2_v3_parser.hpp/cpp
```

## Yêu cầu

- Android NDK
- CMake 3.22.1+
- OpenSSL (được cung cấp bởi Android NDK)
- Android Studio với hỗ trợ C++

## Sử dụng

### 1. Xác minh chữ ký APK

```java
String apkPath = "/path/to/your/app.apk";
String result = MainActivity.verifyApkSignature(apkPath);
// result là JSON string: {"success":true/false, "error_message":"...", ...}
```

### 2. Lấy chứng chỉ Base64

```java
String apkPath = "/path/to/your/app.apk";
String certBase64 = MainActivity.getCertificateBase64(apkPath);
// Trả về chứng chỉ dưới dạng Base64 string
```

## API JNI

### `verifyApkSignature(String apkPath)`

Xác minh chữ ký APK và trả về kết quả dưới dạng JSON:

```json
{
  "success": true,
  "error_message": "",
  "signature_blocks_count": 1,
  "certificates_count": 1,
  "first_certificate_base64": "MII..."
}
```

### `getCertificateBase64(String apkPath)`

Trả về chứng chỉ đầu tiên từ APK dưới dạng Base64 string.

## Cấu hình CMake

Thư viện được cấu hình trong `CMakeLists.txt`:
- Include thư mục `Includes/` để tìm headers
- Thêm tất cả file `.cpp` của thư viện vào build
- Link với OpenSSL (`crypto`) để xử lý chứng chỉ

## Xây dựng

1. Mở dự án trong Android Studio
2. Đảm bảo Android NDK đã được cài đặt
3. Build dự án (Build > Make Project)
4. Chạy trên thiết bị hoặc emulator

## Ghi chú

- Thư viện sử dụng OpenSSL để xử lý chứng chỉ X.509
- Hỗ trợ APK Signature Scheme v2 và v3
- Tương thích với Android API level 24+

## Setup GitHub

### 1. Khởi tạo Git Repository

```bash
git init
git add .
git commit -m "Initial commit: APK Signature Verification Library"
```

### 2. Tạo Repository trên GitHub

1. Đăng nhập vào [GitHub](https://github.com)
2. Click "New repository"
3. Đặt tên repository (ví dụ: `apksig-android`)
4. Chọn **Public**
5. **KHÔNG** tích vào "Initialize with README" (đã có sẵn)
6. Click "Create repository"

### 3. Push Code lên GitHub

```bash
# Thêm remote repository
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git

# Đổi tên branch chính (nếu cần)
git branch -M main

# Push code lên GitHub
git push -u origin main
```

### 4. Cấu hình Git (nếu chưa có)

```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

### 5. Files Quan Trọng đã được Setup

- ✅ `.gitignore` - Đã cấu hình để loại bỏ build files, IDE files
- ✅ `README.md` - Tài liệu hướng dẫn
- ✅ `local.properties` - Đã được ignore (chứa SDK path local)

### 6. Lưu ý khi Push

- **KHÔNG** commit `local.properties` (đã có trong .gitignore)
- **KHÔNG** commit keystore files (`.jks`, `.keystore`)
- **KHÔNG** commit build artifacts (`.apk`, `build/`, `.gradle/`)
- OpenSSL prebuilt libraries trong `app/src/main/cpp/Includes/curl/` sẽ được commit (cần thiết cho build)

## License

Dự án này sử dụng thư viện apksig dựa trên [Android AOSP apksig](https://android.googlesource.com/platform/tools/apksig/) được phát hành dưới Apache License 2.0.

## Tác giả

Dự án mẫu cho thư viện apksig C++ - Port từ Android AOSP apksig Java library

