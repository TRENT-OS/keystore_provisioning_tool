# keystore_provisioning_tool

A tool used to create an image that contains a valid keystore with already imported 
keys and ready to be used by the application.  

### Build

An out-of-source-folder build is the default when executing the build script 
in the root directory of the repository - a folder build is created which contains 
all of the artifacts.

    ./build.sh

### Usage

The tool imports the keys that are contained in the xml file in the repository root 
directory into the keystore from which the resulting binary image is produced. 
To use the tool, run the run.sh script with the following arguments:
    1) path to the input xml containing the key info
    2) path to the provisioning tool binary
    3) path for the output binary image (for example the build dir of the mqtt_proxy_demo)

    ./run.sh keysExample.xml ./build/src/keystore_provisioning_tool ../mqtt_proxy_demo/build/nvm_06