#
# Key Provisioning Tool
#
# Copyright (C) 2019-2022, HENSOLDT Cyber GmbH
#

cmake_minimum_required(VERSION 3.10)

#-------------------------------------------------------------------------------
# use the SDK
find_package("os-sdk" REQUIRED)
os_sdk_create_config_project("system_config" "config.h")
os_sdk_import_core_api()
os_sdk_import_libs()


#-------------------------------------------------------------------------------
project(keystore_provisioning_tool C)

add_executable(${PROJECT_NAME}
    src/keyStoreProvisioningTool.c
)

target_compile_options(${PROJECT_NAME}
    PRIVATE
        -Wall
        -Werror
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        system_config
        os_core_api
        lib_debug
        lib_host
        os_crypto
        os_filesystem
        os_keystore
)
