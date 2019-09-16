#!/bin/bash -ue
BUILD_DIR=./build

if [[ ! -e ${BUILD_DIR} ]]; then
    # use subshell to configure the build
    mkdir -p ${BUILD_DIR}
fi

cd ${BUILD_DIR}

cmake ../
make