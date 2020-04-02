cmake_minimum_required(VERSION 3.10)

#-------------------------------------------------------------------------------
# configure and use the SDK

set(PAGE_SIZE_VALUE 4096 CACHE STRING "" FORCE)
set(NO_KERNEL_BUILD ON CACHE BOOL "")

set(OS_SDK_PASSIVE_CMAKE ON)
include(${OS_SDK_SOURCE_PATH}/CMakeLists.txt)

seos_set_config_file(config.h)

seos_use_libs(
    SEOS_LIBS
    SEOS_CRYPTO
    SEOS_CRYPTO_IMPL_MBEDTLS
    SEOS_FILESYSTEM_SPIFFS_LEGACY
    SEOS_KEYSTORE
)

add_subdirectory(${SEOS_LIBS_DIR} sdk_build)

set(OS_LIBS_KEYSTORE "${SEOS_LIBS_DIR}/seos_keystore")

#-------------------------------------------------------------------------------

project(keystore_provisioning_tool C)

add_executable(${PROJECT_NAME}
    src/keyStoreProvisioningTool.c
    src/FileNVM.c
    ${OS_LIBS_KEYSTORE}/src/AesNvm.c
)

target_include_directories(${PROJECT_NAME}
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}  # for config.h
        ${OS_LIBS_KEYSTORE}/src    # for AesNvm.h
)

target_compile_options(${PROJECT_NAME}
    PUBLIC
        -Wall
        -Werror
)

target_compile_definitions(${PROJECT_NAME}
    PRIVATE
        PAGE_SIZE=${PAGE_SIZE_VALUE}
)

target_link_libraries(${PROJECT_NAME}
    seos_core_api
    seos_libs
    seos_crypto
    seos_filesystem_spiffs_legacy
    seos_keystore
)



