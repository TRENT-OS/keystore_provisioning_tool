cmake_minimum_required(VERSION 3.7.2)

project(keystore_provisioning_tool C)

add_executable(
    ${PROJECT_NAME}

    "app/keyStoreProvisioningTool.c"
    "util/FileNVM.c"
    "util/KeyStoreInit.c"
)

target_compile_options(${PROJECT_NAME}
    PUBLIC
        -Wall
        -Werror
)

target_compile_definitions(${PROJECT_NAME}
    PUBLIC
        ${PUBLIC_TARGET_COMPILE_DEFINITIONS}
    PRIVATE
        ${PRIVATE_TARGET_COMPILE_DEFINITIONS}
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        "include"
        "util"
)

target_link_libraries(${PROJECT_NAME}
    seos_libs
    seos_crypto
    seos_keystore
    seos_core_api
)

