cmake_minimum_required(VERSION 3.7.2)

project(keystore_provisioning_tool C)

set(DEBUG_CONFIG_H_FILE "${CMAKE_SOURCE_DIR}/config.h" CACHE STRING "" FORCE)
set(MEMORY_CONFIG_H_FILE "${CMAKE_SOURCE_DIR}/config.h" CACHE STRING "" FORCE)
set(KEYSTORE_CONFIG_H_FILE "${CMAKE_SOURCE_DIR}/config.h" CACHE STRING "" FORCE)

set(PAGE_SIZE_VALUE 4096 CACHE STRING "" FORCE)

set(NO_KERNEL_BUILD ON CACHE BOOL "")

set(SEOS_LIBS ON CACHE BOOL "")
set(SEOS_CRYPTO ON CACHE BOOL "")
set(SEOS_CRYPTO_IMPL_MBEDTLS ON CACHE BOOL "")
set(SEOS_FILESYSTEM_SPIFFS_LEGACY ON CACHE BOOL "")
set(SEOS_KEYSTORE ON CACHE BOOL "")

add_subdirectory(${SANDBOX_SOURCE_PATH}/projects/libs sandbox_build)

add_executable(
    ${PROJECT_NAME}
    src/keyStoreProvisioningTool.c
    src/FileNVM.c
    src/KeyStoreInit.c
)

target_compile_options(${PROJECT_NAME}
    PUBLIC
        -Wall
        -Werror
)

target_compile_definitions(${PROJECT_NAME}
    #PUBLIC
    #    ${PUBLIC_TARGET_COMPILE_DEFINITIONS}
    PRIVATE
    #    ${PRIVATE_TARGET_COMPILE_DEFINITIONS}
        PAGE_SIZE=${PAGE_SIZE_VALUE}
)

target_link_libraries(${PROJECT_NAME}
    seos_libs
    seos_crypto
    seos_filesystem_spiffs_legacy
    seos_keystore
    seos_core_api
)



