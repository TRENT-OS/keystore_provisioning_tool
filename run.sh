#!/bin/bash -ue

KEYS_XML_INPUT=$1
PROVISIONING_TOOL=$2
OUTPUT_PATH=$3

# calling the python script which parses the xml with key info and 
# calls the provisioning tool with proper arguments
python ./src/xmlParser.py $KEYS_XML_INPUT $PROVISIONING_TOOL

# moves the created binary to the desired path passed as an argument
mv ./nvm_06 $OUTPUT_PATH