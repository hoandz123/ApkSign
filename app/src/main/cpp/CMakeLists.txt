cmake_minimum_required(VERSION 3.22.1)
project("apksign")

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/Includes)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/Includes/curl/openssl-android-${ANDROID_ABI}/include)

add_library(${CMAKE_PROJECT_NAME} SHARED
        native-lib.cpp
        Includes/apksig/apk_reader.cpp
        Includes/apksig/apk_verifier.cpp
        Includes/apksig/certificate_extractor.cpp
        Includes/apksig/digest_verifier.cpp
        Includes/apksig/signing_block_locator.cpp
        Includes/apksig/signing_block_parser.cpp
        Includes/apksig/v2_v3_parser.cpp)

add_library(libcrypto STATIC IMPORTED)
set_target_properties(libcrypto PROPERTIES 
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/Includes/curl/openssl-android-${ANDROID_ABI}/lib/libcrypto.a
)

target_link_libraries(${CMAKE_PROJECT_NAME}
        android
        log
        z
        atomic
        libcrypto)