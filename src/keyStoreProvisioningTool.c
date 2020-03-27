/**
 * @addtogroup CryptoApi_Tests
 * @{
 *
 * @file testRunner.c
 *
 * @brief top level test for the crypto API and the key store API
 *
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
#include <stdio.h>
#include <stdbool.h>
#include "LibDebug/Debug.h"

#include "SeosKeyStore.h"
#include "SeosKeyStoreClient.h"

#include "SeosKeyStoreApi.h"

#include "OS_Crypto.h"

#include "AesNvm.h"
#include "FileNVM.h"
#include "SeosSpiffs.h"
#include "SpiffsFileStream.h"
#include "SpiffsFileStreamFactory.h"

#include "config.h"

/* Defines -------------------------------------------------------------------*/
#define NVM_PARTITION_SIZE          (1024*128)
#define NVM_PARTITION_NAME          "nvm_06"

#define NVM_CHANNEL_NUMBER          (6)
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
}
ProvisioningTool_importType;


typedef struct {
    OS_Crypto_Handle_t  hCrypto;

    SeosKeyStore        keyStore;

    FileNVM             fileNvm;
    AesNvm              aesNvm;
    SeosSpiffs          fs;
    FileStreamFactory*  fileStreamFactory;
} app_ctx_t;


/* Macros --------------------------------------------------------------------*/
#define LEN_BITS_TO_BYTES(lenBits)  (lenBits / CHAR_BIT + ((lenBits % CHAR_BIT) ? 1 : 0))


/* Private functions ---------------------------------------------------------*/

//------------------------------------------------------------------------------
static seos_err_t
create_and_import_aes_key(
    app_ctx_t*       app_ctx,
    char*            keyName,
    bool             isKeyExportable,
    unsigned int     keyLenBits,
    char*            keyBytes)
{
    seos_err_t ret;
    OS_CryptoKey_Data_t keyData;

    if (strlen(keyBytes) == KEY_BYTES_EMPTY_STRING_LEN
        && !strncmp(keyBytes, KEY_BYTES_EMPTY_STRING, KEY_BYTES_EMPTY_STRING_LEN))
    {
        Debug_LOG_DEBUG("\nGenerating AES key:\n   key name = %s\n   key length = %u\n   key exportable = %u\n\n",
                        keyName, keyLenBits, isKeyExportable);

        OS_CryptoKey_Spec_t keySpec =
        {
            .type = OS_CryptoKey_SPECTYPE_BITS,
            .key.type = OS_CryptoKey_TYPE_AES,
            .key.attribs.exportable = isKeyExportable,
            .key.params.bits = keyLenBits
        };

        OS_CryptoKey_Handle_t hKey;
        ret = OS_CryptoKey_generate(&hKey, app_ctx->hCrypto, &keySpec);
        if (SEOS_SUCCESS != ret)
        {
            Debug_LOG_DEBUG("OS_CryptoKey_generate failed with err %d", ret);
            return SEOS_ERROR_GENERIC;
        }

        ret = OS_CryptoKey_export(hKey, &keyData);
        if (SEOS_SUCCESS != ret)
        {
            Debug_LOG_DEBUG("OS_CryptoKey_export failed with err %d", ret);
            return SEOS_ERROR_GENERIC;
        }

    }
    else
    {
        Debug_LOG_DEBUG("\nImporting AES key:\n   key name = %s\n   key length = %u\n   key exportable = %u\n   key bytes = %s\n\n",
                        keyName, keyLenBits, isKeyExportable, keyBytes);

        keyData.type = OS_CryptoKey_TYPE_AES;
        keyData.attribs.exportable = isKeyExportable;
        memcpy(keyData.data.aes.bytes, keyBytes, LEN_BITS_TO_BYTES(keyLenBits));
        keyData.data.aes.len = LEN_BITS_TO_BYTES(keyLenBits);
    }

    ret = SeosKeyStoreApi_importKey(
            &(app_ctx->keyStore.parent),
            keyName,
            &keyData,
            sizeof(keyData));
    if (SEOS_SUCCESS != ret)
    {
        Debug_LOG_DEBUG("SeosKeyStoreApi_importKey failed with err %d", ret);
        return SEOS_ERROR_GENERIC;
    }

    return SEOS_SUCCESS;
}


//------------------------------------------------------------------------------
static seos_err_t
create_and_import_key_pair(
    app_ctx_t*       app_ctx,
    unsigned int     importType,
    char*            keyNamePrv,
    char*            keyNamePub,
    bool             isKeyExportable,
    unsigned int     keyLenBits)
{
    seos_err_t ret;

    OS_CryptoKey_Spec_t keySpec =
    {
        .type = OS_CryptoKey_SPECTYPE_BITS,
        .key.attribs.exportable = isKeyExportable,
        .key.params.bits = keyLenBits
    };

    switch (importType)
    {
    case RSA_KEY_PAIR:
        Debug_LOG_DEBUG("\nGenerating RSA key pair:\n   private key name = %s\n   public key name = %s\n   key length = %u\n   key exportable = %u\n\n",
                        keyNamePrv, keyNamePub, keyLenBits, isKeyExportable);
        keySpec.key.type = OS_CryptoKey_TYPE_RSA_PRV;
        break;

    case DH_KEY_PAIR:
        Debug_LOG_DEBUG("\nGenerating DH key pair:\n   private key name = %s\n   public key name = %s\n   key length = %u\n   key exportable = %u\n\n",
                        keyNamePrv, keyNamePub, keyLenBits, isKeyExportable);
        keySpec.key.type = OS_CryptoKey_TYPE_DH_PRV;
        break;

    case SECP256R1_KEY_PAIR:
        Debug_LOG_DEBUG("\nGenerating SECP256r1 key pair:\n   private key name = %s\n   public key name = %s\n   key length = %u\n   key exportable = %u\n\n",
                        keyNamePrv, keyNamePub, keyLenBits, isKeyExportable);
        keySpec.key.type = OS_CryptoKey_TYPE_SECP256R1_PRV;
        break;

    default:
        Debug_LOG_ERROR("\n\nInvalid import type %u!\n\n\n\n", importType);
        return SEOS_ERROR_GENERIC;
    }

    OS_CryptoKey_Handle_t hKeyPrv;
    ret = OS_CryptoKey_generate(&hKeyPrv, app_ctx->hCrypto, &keySpec);
    if (SEOS_SUCCESS != ret)
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
    if (SEOS_SUCCESS != ret)
    {
        Debug_LOG_DEBUG("OS_CryptoKey_makePublic failed with err %d", ret);
        return SEOS_ERROR_GENERIC;
    }

    OS_CryptoKey_Data_t keyData;
    ret = OS_CryptoKey_export(hKeyPrv, &keyData);
    if (SEOS_SUCCESS != ret)
    {
        Debug_LOG_DEBUG("OS_CryptoKey_export failed with err %d", ret);
        return SEOS_ERROR_GENERIC;
    }

    ret = SeosKeyStoreApi_importKey(
            &(app_ctx->keyStore.parent),
            keyNamePrv,
            &keyData,
            sizeof(keyData));
    if (SEOS_SUCCESS != ret)
    {
        Debug_LOG_DEBUG("SeosKeyStoreApi_importKey failed with err %d", ret);
        return SEOS_ERROR_GENERIC;
    }

    ret = OS_CryptoKey_export(hKeyPub, &keyData);
    if (SEOS_SUCCESS != ret)
    {
        Debug_LOG_DEBUG("OS_CryptoKey_export failed with err %d", ret);
        return SEOS_ERROR_GENERIC;
    }

    ret = SeosKeyStoreApi_importKey(
            &(app_ctx->keyStore.parent),
            keyNamePub,
            &keyData,
            sizeof(keyData));
    if (SEOS_SUCCESS != ret)
    {
        Debug_LOG_DEBUG("SeosKeyStoreApi_importKey failed with err %d", ret);
        return SEOS_ERROR_GENERIC;
    }

    return SEOS_SUCCESS;
}


//------------------------------------------------------------------------------
static int
dummyEntropyFunc(
    void*           ctx,
    unsigned char*  buf,
    size_t          len)
{
    return 0;
}


//------------------------------------------------------------------------------
static seos_err_t
initialize_crypto(
    app_ctx_t* app_ctx)
{
    OS_Crypto_Config_t cfgCrypto =
    {
        .mode = OS_Crypto_MODE_LIBRARY,
        .mem = {
            .malloc = malloc,
            .free = free,
        },
        .impl.lib.rng = {
            .entropy = dummyEntropyFunc,
            .context = NULL
        }
    };

    // Open local instance of Crypto API
    seos_err_t ret = OS_Crypto_init( &(app_ctx->hCrypto), &cfgCrypto);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoLib_init failed with error code %d!",
                        __func__, ret);
        return SEOS_ERROR_GENERIC;
    }

    return SEOS_SUCCESS;
}


//------------------------------------------------------------------------------
static seos_err_t
prepare_keystore_NVM(
    app_ctx_t* app_ctx)
{
    // create and initialize an nvm instance that writes directly to a file
    if (!FileNVM_ctor( &(app_ctx->fileNvm), NVM_PARTITION_NAME))
    {
        Debug_LOG_ERROR("%s: Failed to initialize FileNVM!", __func__);
        return SEOS_ERROR_GENERIC;
    }

    static const OS_CryptoKey_Data_t masterKeyData =
    {
        .type = OS_CryptoKey_TYPE_AES,
        .data.aes.len = sizeof(KEYSTORE_KEY_AES)-1,
        .data.aes.bytes = KEYSTORE_KEY_AES
    };

    if (!AesNvm_ctor(
            &(app_ctx->aesNvm),
            FileNVM_TO_NVM( &(app_ctx->fileNvm) ),
            KEYSTORE_IV,
            &masterKeyData))
    {
        Debug_LOG_ERROR("%s: Failed to initialize AesNvm!", __func__);
        return SEOS_ERROR_GENERIC;
    }

    if (!SeosSpiffs_ctor(
            &(app_ctx->fs),
            AesNvm_TO_NVM( &(app_ctx->aesNvm) ),
            NVM_PARTITION_SIZE,
            0))
    {
        Debug_LOG_ERROR("%s: Failed to initialize spiffs!", __func__);
        return SEOS_ERROR_GENERIC;
    }

    seos_err_t ret = SeosSpiffs_mount( &(app_ctx->fs) );
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: spiffs mount failed with error code %d!",
                        __func__, ret);

        return SEOS_ERROR_GENERIC;
    }

    app_ctx->fileStreamFactory = SpiffsFileStreamFactory_TO_FILE_STREAM_FACTORY(
                                    SpiffsFileStreamFactory_getInstance(
                                        &(app_ctx->fs)));
    if (app_ctx->fileStreamFactory == NULL)
    {
        Debug_LOG_ERROR("%s: Failed to get the SpiffsFileStreamFactory instance!",
                        __func__);
        return SEOS_ERROR_GENERIC;
    }

    return SEOS_SUCCESS;
}


//------------------------------------------------------------------------------
static seos_err_t
initializeApp(
    app_ctx_t* app_ctx)
{
    seos_err_t ret;

    ret = initialize_crypto(app_ctx);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: initialize_crypto failed with error code %d!",
                        __func__, ret);
        return SEOS_ERROR_GENERIC;
    }

    // prepave NVM subsystem for keystore
    ret = prepare_keystore_NVM(app_ctx);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: prepare_keystore_NVM failed with error code %d!",
                        __func__, ret);
        return SEOS_ERROR_GENERIC;
    }

    // setup keystore with fielstream based on NVM subsystem
    ret = SeosKeyStore_init(
            &(app_ctx->keyStore),
            app_ctx->fileStreamFactory,
            app_ctx->hCrypto,
            KEY_STORE_INSTANCE_NAME);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosKeyStore_init failed with error code %d!",
                        __func__, ret);
        return SEOS_ERROR_GENERIC;
    }

    return SEOS_SUCCESS;
}


//------------------------------------------------------------------------------
static void
deinitializeApp(
    app_ctx_t* app_ctx)
{
    SeosKeyStore_deInit( &(app_ctx->keyStore.parent) );

    FileStreamFactory_dtor(app_ctx->fileStreamFactory);
    SeosSpiffs_dtor( &(app_ctx->fs) );
    // ToDo: AesNvm_dtor
    FileNVM_dtor( FileNVM_TO_NVM( &(app_ctx->fileNvm) ) );

    OS_Crypto_free(app_ctx->hCrypto);
}


/* Application ---------------------------------------------------------------*/
int main(
    int    argc,
    char*  argv[])
{
    int exit_code = 0;
    seos_err_t ret;
    app_ctx_t app_ctx;

    ret = initializeApp(&app_ctx);
    if (ret != SEOS_SUCCESS)
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
        bool isKeyExportable = atoi(argv[3]);
        unsigned int keyLenBits = atoi(argv[4]);
        char* keyBytes = argv[5];

        ret = create_and_import_aes_key(
                &app_ctx,
                keyName,
                isKeyExportable,
                keyLenBits,
                keyBytes);
        if (ret != SEOS_SUCCESS)
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
        bool isKeyExportable = atoi(argv[4]);
        unsigned int keyLenBits = atoi(argv[5]);

        ret = create_and_import_key_pair(
                &app_ctx,
                importType,
                keyNamePrv,
                keyNamePub,
                isKeyExportable,
                keyLenBits);
        if (ret != SEOS_SUCCESS)
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
