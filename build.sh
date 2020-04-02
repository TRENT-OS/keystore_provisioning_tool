#!/bin/bash -ue

BUILD_SCRIPT_DIR=$(cd `dirname $0` && pwd)

# by convention, the build always happens in a dedicated sub folder of the
# current folder where the script is invoked in
BUILD_DIR=build

if [ "$#" -ne 1 ]; then
    echo "Illegal number of parameters, OS_SDK_PATH needed!"
    exit 1
fi
OS_SDK_PATH=$1

if [[ -e ${BUILD_DIR} ]] && [[ ! -e ${BUILD_DIR}/rules.ninja ]]; then
    echo "clean broken build folder and re-initialize it"
    rm -rf ${BUILD_DIR}
fi

if [[ ! -e ${BUILD_DIR} ]]; then
    # use subshell to configure the build
    (
        mkdir -p ${BUILD_DIR}
        cd ${BUILD_DIR}

        CMAKE_PARAMS=(
            -DOS_SDK_SOURCE_PATH:STRING=${OS_SDK_PATH}
        )

        cmake ${CMAKE_PARAMS[@]} -G Ninja ${BUILD_SCRIPT_DIR}
    )
fi

# build in subshell
(
    cd ${BUILD_DIR}
    ninja
)
