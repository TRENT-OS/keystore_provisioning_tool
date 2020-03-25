cmake_minimum_required(VERSION 3.7.2)

#-------------------------------------------------------------------------------
# configure and use sandbox

set(PAGE_SIZE_VALUE 4096 CACHE STRING "" FORCE)
set(NO_KERNEL_BUILD ON CACHE BOOL "")

set(SEOS_SANDBOX_PASSIVE_CMAKE ON)
include(${SANDBOX_SOURCE_PATH}/CMakeLists.txt)

SET(SEOS_LIBS_KEYSTORE "${SEOS_LIBS_DIR}/seos_keystore")

seos_set_config_file(config.h)

seos_use_libs(
    SEOS_LIBS
    SEOS_CRYPTO
    SEOS_CRYPTO_IMPL_MBEDTLS
    SEOS_FILESYSTEM_SPIFFS_LEGACY
    SEOS_KEYSTORE
)

add_subdirectory(${SEOS_LIBS_DIR} sandbox_build)

#-------------------------------------------------------------------------------

project(keystore_provisioning_tool C)

add_executable(${PROJECT_NAME}
    src/keyStoreProvisioningTool.c
    src/FileNVM.c
    src/KeyStoreInit.c
    ${SEOS_LIBS_KEYSTORE}/src/AesNvm.c
)

target_include_directories(${PROJECT_NAME}
    PRIVATE
        ${SEOS_LIBS_KEYSTORE}/src
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



