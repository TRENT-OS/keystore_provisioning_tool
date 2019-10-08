#!/bin/bash -ue

if [ "$#" -ne 3 ]; then
    echo "Illegal number of parameters, SOURCE_DIR, BUILD_DIR and SANDBOX_PATH needed!"
    exit 1
fi

SOURCE_DIR=$1
BUILD_DIR=$2
SANDBOX_PATH=$3

if [[ ! -e ${BUILD_DIR} ]]; then
    mkdir -p ${BUILD_DIR}
fi

cmake -B${BUILD_DIR}/tool_build \
      -H${SOURCE_DIR} \
      -DSANDBOX_SOURCE_PATH:STRING=${SANDBOX_PATH} \
      -DSANDBOX_BUILD_PATH:STRING=${BUILD_DIR}/sandbox_build

cd ${BUILD_DIR}/tool_build

make