/*
 * Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
 */

#include "OS_Keystore.h"
#include "OS_Crypto.h"
#include "OS_FileSystem.h"

#include "lib_host/HostEntropy.h"
#include "lib_host/HostStorage.h"

#include "lib_debug/Debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

/* Defines -------------------------------------------------------------------*/
#define KEY_STORE_INSTANCE_NAME     "KeyStore1"
#define KEY_BYTES_EMPTY_STRING      "0"
#define KEY_BYTES_EMPTY_STRING_LEN  1

// number of command line arguments required to perform
// import/generate for each key type + 1 refers to the
// 0. argument which is the tool itself
#define NUM_OF_ARGS_AES         (5 + 1)
#define NUM_OF_ARGS_KEY_PAIR    (5 + 1)

typedef enum
{
    AES_KEY,
    RSA_KEY_PAIR,
    DH_KEY_PAIR,
    SECP256R1_KEY_PAIR
} ProvisioningTool_importType;

typedef struct
{
    OS_Crypto_Handle_t hCrypto;
    OS_Keystore_Handle_t hKeystore;
    OS_FileSystem_Handle_t hFs;
} app_ctx_t;

extern FakeDataport_t* hostEntropy_port;
static OS_Crypto_Config_t cfgCrypto =
{
    .mode = OS_Crypto_MODE_LIBRARY,
    .entropy = IF_OS_ENTROPY_ASSIGN(
        HostEntropy,
        hostEntropy_port),
};
extern FakeDataport_t* hostStorage_port;
static OS_FileSystem_Config_t cfgFs =
{
    .type = OS_FileSystem_Type_FATFS,
    .size = OS_FileSystem_USE_STORAGE_MAX,
    .storage = IF_OS_STORAGE_ASSIGN(
        HostStorage,
        hostStorage_port),
};

/* Macros --------------------------------------------------------------------*/
#define LEN_BITS_TO_BYTES(lenBits)  (lenBits / 8 + ((lenBits % 8) ? 1 : 0))

/* Private functions ---------------------------------------------------------*/

//------------------------------------------------------------------------------
static OS_Error_t
create_and_import_aes_key(
    app_ctx_t*   app_ctx,
    char*        keyName,
    bool         keepLocal,
    unsigned int keyLenBits,
    char*        keyBytes)
{
    OS_Error_t ret;
    OS_CryptoKey_Data_t keyData;

    if (strlen(keyBytes) == KEY_BYTES_EMPTY_STRING_LEN
        && !strncmp(keyBytes, KEY_BYTES_EMPTY_STRING, KEY_BYTES_EMPTY_STRING_LEN))
    {
        Debug_LOG_DEBUG("\nGenerating AES key:\n   key name = %s\n   key length = %u\n   key local = %u\n\n",
                        keyName, keyLenBits, keepLocal);

        OS_CryptoKey_Spec_t keySpec =
        {
            .type = OS_CryptoKey_SPECTYPE_BITS,
            .key.type = OS_CryptoKey_TYPE_AES,
            .key.attribs.keepLocal = keepLocal,
            .key.params.bits = keyLenBits
        };

        OS_CryptoKey_Handle_t hKey;
        ret = OS_CryptoKey_generate(&hKey, app_ctx->hCrypto, &keySpec);
        if (OS_SUCCESS != ret)
        {
            Debug_LOG_DEBUG("OS_CryptoKey_generate failed with err %d", ret);
            return OS_ERROR_GENERIC;
        }

        ret = OS_CryptoKey_export(hKey, &keyData);
        if (OS_SUCCESS != ret)
        {
            Debug_LOG_DEBUG("OS_CryptoKey_export failed with err %d", ret);
            return OS_ERROR_GENERIC;
        }

    }
    else
    {
        Debug_LOG_DEBUG("\nImporting AES key:\n   key name = %s\n   key length = %u\n   key local = %u\n   key bytes = %s\n\n",
                        keyName, keyLenBits, keepLocal, keyBytes);

        keyData.type = OS_CryptoKey_TYPE_AES;
        keyData.attribs.keepLocal = keepLocal;
        memcpy(keyData.data.aes.bytes, keyBytes, LEN_BITS_TO_BYTES(keyLenBits));
        keyData.data.aes.len = LEN_BITS_TO_BYTES(keyLenBits);
    }

    ret = OS_Keystore_storeKey(
              app_ctx->hKeystore,
              keyName,
              &keyData,
              sizeof(keyData));
    if (OS_SUCCESS != ret)
    {
        Debug_LOG_DEBUG("OS_Keystore_storeKey failed with err %d", ret);
        return OS_ERROR_GENERIC;
    }

    return OS_SUCCESS;
}


//------------------------------------------------------------------------------
static OS_Error_t
create_and_import_key_pair(
    app_ctx_t*   app_ctx,
    unsigned int importType,
    char*        keyNamePrv,
    char*        keyNamePub,
    bool         keepLocal,
    unsigned int keyLenBits)
{
    OS_Error_t ret;

    OS_CryptoKey_Spec_t keySpec =
    {
        .type = OS_CryptoKey_SPECTYPE_BITS,
        .key.attribs.keepLocal = keepLocal,
        .key.params.bits = keyLenBits
    };

    switch (importType)
    {
    case RSA_KEY_PAIR:
        Debug_LOG_DEBUG("\nGenerating RSA key pair:\n   private key name = %s\n   public key name = %s\n   key length = %u\n   key local = %u\n\n",
                        keyNamePrv, keyNamePub, keyLenBits, keepLocal);
        keySpec.key.type = OS_CryptoKey_TYPE_RSA_PRV;
        break;

    case DH_KEY_PAIR:
        Debug_LOG_DEBUG("\nGenerating DH key pair:\n   private key name = %s\n   public key name = %s\n   key length = %u\n   key local = %u\n\n",
                        keyNamePrv, keyNamePub, keyLenBits, keepLocal);
        keySpec.key.type = OS_CryptoKey_TYPE_DH_PRV;
        break;

    case SECP256R1_KEY_PAIR:
        Debug_LOG_DEBUG("\nGenerating SECP256r1 key pair:\n   private key name = %s\n   public key name = %s\n   key length = %u\n   key local = %u\n\n",
                        keyNamePrv, keyNamePub, keyLenBits, keepLocal);
        keySpec.key.type = OS_CryptoKey_TYPE_SECP256R1_PRV;
        break;

    default:
        Debug_LOG_ERROR("\n\nInvalid import type %u!\n\n\n\n", importType);
        return OS_ERROR_GENERIC;
    }

    OS_CryptoKey_Handle_t hKeyPrv;
    ret = OS_CryptoKey_generate(&hKeyPrv, app_ctx->hCrypto, &keySpec);
    if (OS_SUCCESS != ret)
    {
        Debug_LOG_DEBUG("OS_CryptoKey_generate failed with err %d", ret);
        return false;
    }

    OS_CryptoKey_Handle_t hKeyPub;
    ret = OS_CryptoKey_makePublic(
              &hKeyPub,
              app_ctx->hCrypto,
              hKeyPrv,
              &keySpec.key.attribs);
    if (OS_SUCCESS != ret)
    {
        Debug_LOG_DEBUG("OS_CryptoKey_makePublic failed with err %d", ret);
        return OS_ERROR_GENERIC;
    }

    OS_CryptoKey_Data_t keyData;
    ret = OS_CryptoKey_export(hKeyPrv, &keyData);
    if (OS_SUCCESS != ret)
    {
        Debug_LOG_DEBUG("OS_CryptoKey_export failed with err %d", ret);
        return OS_ERROR_GENERIC;
    }

    ret = OS_Keystore_storeKey(
              app_ctx->hKeystore,
              keyNamePrv,
              &keyData,
              sizeof(keyData));
    if (OS_SUCCESS != ret)
    {
        Debug_LOG_DEBUG("OS_Keystore_storeKey failed with err %d", ret);
        return OS_ERROR_GENERIC;
    }

    ret = OS_CryptoKey_export(hKeyPub, &keyData);
    if (OS_SUCCESS != ret)
    {
        Debug_LOG_DEBUG("OS_CryptoKey_export failed with err %d", ret);
        return OS_ERROR_GENERIC;
    }

    ret = OS_Keystore_storeKey(
              app_ctx->hKeystore,
              keyNamePub,
              &keyData,
              sizeof(keyData));
    if (OS_SUCCESS != ret)
    {
        Debug_LOG_DEBUG("OS_Keystore_storeKey failed with err %d", ret);
        return OS_ERROR_GENERIC;
    }

    return OS_SUCCESS;
}


//------------------------------------------------------------------------------
static OS_Error_t
initializeApp(
    app_ctx_t* app_ctx)
{
    OS_Error_t ret;

    // Open local instance of Crypto API
    ret = OS_Crypto_init( &(app_ctx->hCrypto), &cfgCrypto);
    if (ret != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_Crypto_init failed with error code %d!", ret);
        return ret;
    }

    // Open local instance of FS
    ret = OS_FileSystem_init(&app_ctx->hFs, &cfgFs);
    if (ret != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_FileSystem_init() failed with %d", ret);
        return ret;
    }

    // Try mounting, if it fails we format the disk again and try another time
    ret = OS_FileSystem_mount(app_ctx->hFs);
    if (ret != OS_SUCCESS)
    {
        Debug_LOG_INFO("Mounting fileystem failed, formatting the storage now");
        ret = OS_FileSystem_format(app_ctx->hFs);
        if (ret != OS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_FileSystem_format() failed with %d", ret);
            return ret;
        }
        ret = OS_FileSystem_mount(app_ctx->hFs);
        if (ret != OS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_FileSystem_mount() finally failed with %d", ret);
            return ret;
        }
    }
    else
    {
        Debug_LOG_INFO("Mounted existing fileystem");
    }

    // Setup keystore
    ret = OS_Keystore_init(&app_ctx->hKeystore,
                           app_ctx->hFs,
                           app_ctx->hCrypto,
                           KEY_STORE_INSTANCE_NAME);
    if (ret != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: OS_Keystore_init failed with error code %d!",
                        __func__, ret);
        return OS_ERROR_GENERIC;
    }

    return ret;
}


//------------------------------------------------------------------------------
static void
deinitializeApp(
    app_ctx_t* app_ctx)
{
    OS_Keystore_free(app_ctx->hKeystore);
    OS_FileSystem_unmount(app_ctx->hFs);
    OS_FileSystem_free(app_ctx->hFs);
    OS_Crypto_free(app_ctx->hCrypto);
}


/* Application ---------------------------------------------------------------*/
int main(
    int   argc,
    char* argv[])
{
    int exit_code = 0;
    OS_Error_t ret;
    app_ctx_t app_ctx;

    ret = initializeApp(&app_ctx);
    if (ret != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: initializeApp failed with error code %d!",
                        __func__, ret);
        return -1;
    }

    // argv[0] is the binary name, argv[1] would be the first parameter.
    if (argc < 2)
    {
        Debug_LOG_ERROR("no arguments specified");
        exit_code = -1;
        goto exit;
    }

    unsigned int importType = atoi(argv[1]);
    if (importType == AES_KEY)
    {
        if (argc != NUM_OF_ARGS_AES)
        {
            Debug_LOG_ERROR("%u is an invalid number of arguments to import/generate an aes key! Required %u",
                            argc, NUM_OF_ARGS_AES);
            exit_code = -1;
            goto exit;
        }

        char* keyName = argv[2];
        bool keepLocal = atoi(argv[3]);
        unsigned int keyLenBits = atoi(argv[4]);
        char* keyBytes = argv[5];

        ret = create_and_import_aes_key(
                  &app_ctx,
                  keyName,
                  keepLocal,
                  keyLenBits,
                  keyBytes);
        if (ret != OS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: create_and_import_aes_key failed with error code %d!",
                            __func__, ret);
            exit_code = -1;
            goto exit;
        }
    }
    else
    {
        if (argc != NUM_OF_ARGS_KEY_PAIR)
        {
            Debug_LOG_ERROR("%u is an invalid number of arguments to generate a key pair! Required %u",
                            argc, NUM_OF_ARGS_KEY_PAIR);
            goto exit;
        }

        char* keyNamePrv = argv[2];
        char* keyNamePub = argv[3];
        bool keepLocal = atoi(argv[4]);
        unsigned int keyLenBits = atoi(argv[5]);

        ret = create_and_import_key_pair(
                  &app_ctx,
                  importType,
                  keyNamePrv,
                  keyNamePub,
                  keepLocal,
                  keyLenBits);
        if (ret != OS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: create_and_import_key_pair failed with error code %d!",
                            __func__, ret);
            exit_code = -1;
            goto exit;
        }
    }

exit:
    deinitializeApp(&app_ctx);

    return exit_code;
}

///@}
