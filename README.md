# Keystore Provisioning Tool

A tool used to create an image that contains a valid keystore with already imported
keys and ready to be used by the application.

### Build

The build script needs to be called with 3 arguments:

    1)path of the source directory
    2)path of the build directory
    3)path of the SDK

For an example directory structure as follows

```bash
.
|____seos_sandbox
|____src
|    |____repository_contents
```

    ./src/build.sh ./src ./build ./sdk

will generate the following

```bash
.
|____seos_sandbox
|____src
|    |____repository_contents
|____build
|    |____tool_build
|    |____sandbox_build
```

### Usage

The tool imports the keys that are contained in the xml file in the repository root
directory into the keystore from which the resulting binary image is produced.
To use the tool, run the run.sh script with the following arguments:

    1) path to the input xml containing the key info
    2) path to the provisioning tool binary
    3) path for the output binary image (for example the build dir of the mqtt_proxy_demo)

    ./run.sh keysExample.xml ./build/tool_build/src/keystore_provisioning_tool ../mqtt_proxy_demo/build/nvm_06
