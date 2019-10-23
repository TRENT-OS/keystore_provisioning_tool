cmake_minimum_required(VERSION 3.7.2)

set(DEBUG_CONFIG_H_FILE
        "${CMAKE_SOURCE_DIR}/config.h"
        CACHE STRING "" FORCE
)
set(MEMORY_CONFIG_H_FILE
        "${CMAKE_SOURCE_DIR}/config.h"
        CACHE STRING "" FORCE
)
set(KEYSTORE_CONFIG_H_FILE
        "${CMAKE_SOURCE_DIR}/config.h"
        CACHE STRING "" FORCE
)

set(PAGE_SIZE_VALUE
        4096
        CACHE STRING "" FORCE
)

set(NO_KERNEL_BUILD ON
    CACHE BOOL "string")
set(SEOS_LIBS ON
    CACHE BOOL "string" FORCE)
set(SEOS_CRYPTO ON
    CACHE BOOL "string")
set(SEOS_CRYPTO_IMPL_MBEDTLS ON
    CACHE BOOL "string")
set(SEOS_KEYSTORE ON
    CACHE BOOL "string")
set(SEOS_FILESYSTEM_SPIFFS ON
    CACHE BOOL "string" FORCE)

add_subdirectory(${SANDBOX_SOURCE_PATH}/projects/libs ${SANDBOX_BUILD_PATH})
add_subdirectory(src)