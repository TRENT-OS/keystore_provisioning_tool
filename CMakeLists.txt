#
# Key Provisioning Tool
#
# Copyright (C) 2019-2020, Hensoldt Cyber GmbH
#

cmake_minimum_required(VERSION 3.10)

#-------------------------------------------------------------------------------
# configure and use the SDK

set(OS_SDK_PASSIVE_CMAKE ON)
include(${OS_SDK_SOURCE_PATH}/CMakeLists.txt)

os_set_config_file(config.h)

os_use_libs(
    OS_LIBS
    OS_CRYPTO
    OS_FILESYSTEM_SPIFFS_LEGACY
    OS_KEYSTORE
)

add_subdirectory(${OS_LIBS_DIR} sdk_build)


#-------------------------------------------------------------------------------
project(keystore_provisioning_tool C)

add_executable(${PROJECT_NAME}
    src/keyStoreProvisioningTool.c
    src/FileNVM.c
)

target_include_directories(${PROJECT_NAME}
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}  # for config.h
)

target_compile_options(${PROJECT_NAME}
    PRIVATE
        -Wall
        -Werror
)

target_compile_definitions(${PROJECT_NAME}
    PRIVATE
        PAGE_SIZE=4096
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        os_core_api
        os_libs
        os_crypto
        os_filesystem_spiffs_legacy
        os_keystore
)
