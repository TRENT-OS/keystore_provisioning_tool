#!/bin/bash -ue

BUILD_SCRIPT_DIR=$(cd `dirname $0` && pwd)

if [ "$#" -ne 3 ]; then
    echo "Illegal number of parameters, KEYSTORE_CONFIG_XML, PROVISIONING_TOOL_BIN, OUTPUT_IMAGE needed!"
    exit 1
fi

# XML config file with keystore content
KEYSTORE_CONFIG_XML=$1

# compiled binary of the provisioning tool
PROVISIONING_TOOL_BIN=$2

# name and location of the keystore image
OUTPUT_IMAGE=$3



# call a python script that parses the xml config file with key info and then
# calls the provisioning tool with proper arguments
python \
    ${BUILD_SCRIPT_DIR}/xmlParser.py \
    ${KEYSTORE_CONFIG_XML} \
    ${PROVISIONING_TOOL_BIN}

# move the created keystore image to the desired location
if [ -e ${OUTPUT_IMAGE} ]; then
    echo "deleting existing keystore image"
    rm ${OUTPUT_IMAGE}
fi
mv nvm_06 ${OUTPUT_IMAGE}
