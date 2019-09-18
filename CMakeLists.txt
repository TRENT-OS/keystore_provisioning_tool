cmake_minimum_required(VERSION 3.7.2)

set(DEBUG_CONFIG_H_FILE
        "${CMAKE_SOURCE_DIR}/configs/include/Debug_Config.h"
        CACHE STRING "" FORCE
)
set(MEMORY_CONFIG_H_FILE
        "${CMAKE_SOURCE_DIR}/configs/include/Memory_Config.h"
        CACHE STRING "" FORCE
)
set(KEYSTORE_CONFIG_H_FILE
        "${CMAKE_SOURCE_DIR}/configs/include/KeyStore_Config.h"
        CACHE STRING "" FORCE
)

set(NO_KERNEL_BUILD ON
    CACHE BOOL "string")

set(ENABLE_LINT ON
    CACHE BOOL "string")
set(SEOS_LIBS ON
    CACHE BOOL "string" FORCE)
set(SEOS_CRYPTO ON
    CACHE BOOL "string")
set(SEOS_CRYPTO_IMPL_MBEDTLS ON
    CACHE BOOL "string")
set(SEOS_KEYSTORE ON
    CACHE BOOL "string")
set(SPIFFS ON
    CACHE BOOL "string" FORCE)

add_subdirectory(seos_sandbox/projects/libs)
add_subdirectory(src)