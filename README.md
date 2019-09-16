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
To use the tool, run the run.sh script with 1 argument specifying the path of the 
output binary image.

    ./run.sh outut-path