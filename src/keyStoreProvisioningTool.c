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

#include "KeyStoreInit.h"

#include "config.h"

/* Defines -------------------------------------------------------------------*/
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

/* Macros -------------------------------------------------------------------*/
#define LEN_BITS_TO_BYTES(lenBits)  (lenBits / CHAR_BIT + ((lenBits % CHAR_BIT) ? 1 : 0))

/* Private function prototypes -------------------------------------------------------------------*/
static bool initializeApp(OS_Crypto_Handle_t* hCrypto,
                          SeosKeyStore* localKeyStore,
                          KeyStoreContext* keyStoreCtx);
static void deinitializeApp(OS_Crypto_Handle_t hCrypto,
                            SeosKeyStore* localKeyStore, KeyStoreContext* keyStoreCtx);
static int dummyEntropyFunc(void* ctx, unsigned char* buf, size_t len);
static void generateAndImportKeyPair(OS_Crypto_Handle_t hCrypto,
                                     SeosKeyStoreCtx* keyStoreCtx,
                                     char* keyNamePrv,
                                     char* keyNamePub,
                                     OS_CryptoKey_Spec_t* spec);

/* Private variables -------------------------------------------------------------------*/
static OS_CryptoKey_Handle_t hKey;
static OS_CryptoKey_Data_t keyData;
static OS_CryptoKey_Spec_t keySpec =
{
    .type = OS_CryptoKey_SPECTYPE_BITS
};

/* Application -------------------------------------------------------------------*/
int main(int argc, char* argv[])
{
    OS_Crypto_Handle_t hCrypto;
    SeosKeyStore localKeyStore;
    KeyStoreContext keyStoreCtx;

    seos_err_t err = SEOS_ERROR_GENERIC;
    unsigned int importType = atoi(argv[1]);

    bool keyExportable = false;
    unsigned int keyLenBits = 0;

    /********************************** Initialization ************************************/
    if (!initializeApp(&hCrypto, &localKeyStore, &keyStoreCtx))
    {
        Debug_LOG_ERROR("\n\nFailed to initialize the provisioning tool!\n\n\n\n");
        return 0;
    }

    /********************************** Key creation ************************************/
    if (importType == AES_KEY)
    {
        if (argc != NUM_OF_ARGS_AES)
        {
            Debug_LOG_ERROR("%u is an invalid number of arguments to import/generate an aes key! Required %u",
                            argc, NUM_OF_ARGS_AES);
            goto exit;
        }

        keyExportable = atoi(argv[3]);
        keyLenBits = atoi(argv[4]);

        char* keyBytes = argv[5];
        char* keyName = argv[2];

        if (strlen(keyBytes) == KEY_BYTES_EMPTY_STRING_LEN
            && !strncmp(keyBytes, KEY_BYTES_EMPTY_STRING, KEY_BYTES_EMPTY_STRING_LEN))
        {
            Debug_LOG_DEBUG("\nGenerating AES key:\n   key name = %s\n   key length = %u\n   key exportable = %u\n\n",
                            keyName, keyLenBits, keyExportable);

            keySpec.key.type = OS_CryptoKey_TYPE_AES;
            keySpec.key.attribs.exportable = keyExportable;
            keySpec.key.params.bits = keyLenBits;
            err = OS_CryptoKey_generate(&hKey, hCrypto, &keySpec);
            Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                                  "OS_CryptoKey_generate failed with err %d", err);

            err = OS_CryptoKey_export(hKey, &keyData);
            Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                                  "OS_CryptoKey_export failed with err %d", err);
        }
        else
        {
            Debug_LOG_DEBUG("\nImporting AES key:\n   key name = %s\n   key length = %u\n   key exportable = %u\n   key bytes = %s\n\n",
                            keyName, keyLenBits, keyExportable, keyBytes);

            keyData.type = OS_CryptoKey_TYPE_AES;
            keyData.attribs.exportable = keyExportable;
            memcpy(keyData.data.aes.bytes, keyBytes, LEN_BITS_TO_BYTES(keyLenBits));
            keyData.data.aes.len = LEN_BITS_TO_BYTES(keyLenBits);
        }

        err = SeosKeyStoreApi_importKey(&(localKeyStore.parent), keyName, &keyData,
                                        sizeof(keyData));
        Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                              "SeosKeyStoreApi_importKey failed with err %d", err);
    }
    else
    {
        if (argc != NUM_OF_ARGS_KEY_PAIR)
        {
            Debug_LOG_ERROR("%u is an invalid number of arguments to generate a key pair! Required %u",
                            argc, NUM_OF_ARGS_KEY_PAIR);
            goto exit;
        }

        keyExportable = atoi(argv[4]);
        keyLenBits = atoi(argv[5]);

        char* keyNamePrv = argv[2];
        char* keyNamePub = argv[3];

        keySpec.type = OS_CryptoKey_SPECTYPE_BITS;
        keySpec.key.attribs.exportable = keyExportable;
        keySpec.key.params.bits = keyLenBits;

        switch (importType)
        {
        case RSA_KEY_PAIR:
            Debug_LOG_DEBUG("\nGenerating RSA key pair:\n   private key name = %s\n   public key name = %s\n   key length = %u\n   key exportable = %u\n\n",
                            keyNamePrv, keyNamePub, keyLenBits, keyExportable);
            keySpec.key.type = OS_CryptoKey_TYPE_RSA_PRV;
            break;

        case DH_KEY_PAIR:
            Debug_LOG_DEBUG("\nGenerating DH key pair:\n   private key name = %s\n   public key name = %s\n   key length = %u\n   key exportable = %u\n\n",
                            keyNamePrv, keyNamePub, keyLenBits, keyExportable);
            keySpec.key.type = OS_CryptoKey_TYPE_DH_PRV;
            break;

        case SECP256R1_KEY_PAIR:
            Debug_LOG_DEBUG("\nGenerating SECP256r1 key pair:\n   private key name = %s\n   public key name = %s\n   key length = %u\n   key exportable = %u\n\n",
                            keyNamePrv, keyNamePub, keyLenBits, keyExportable);
            keySpec.key.type = OS_CryptoKey_TYPE_SECP256R1_PRV;
            break;

        default:
            Debug_LOG_ERROR("\n\nInvalid import type %u!\n\n\n\n", importType);
            break;
        }

        generateAndImportKeyPair(hCrypto,
                                 &(localKeyStore.parent),
                                 keyNamePrv,
                                 keyNamePub,
                                 &keySpec);
    }

exit:
    deinitializeApp(hCrypto, &localKeyStore, &keyStoreCtx);

    return 0;
}

/* Private functions -------------------------------------------------------------------*/
static bool initializeApp(OS_Crypto_Handle_t* hCrypto,
                          SeosKeyStore* localKeyStore,
                          KeyStoreContext* keyStoreCtx)
{
    seos_err_t err;
    OS_Crypto_Config_t cfgLocal =
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

    // Open local instance of API
    err = OS_Crypto_init(hCrypto, &cfgLocal);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: OS_CryptoLib_init failed with error code %d!", __func__,
                        err);
        return false;
    }

    static const OS_CryptoKey_Data_t masterKeyData =
    {
        .type = OS_CryptoKey_TYPE_AES,
        .data.aes.len = sizeof(KEYSTORE_KEY_AES)-1,
        .data.aes.bytes = KEYSTORE_KEY_AES
    };

    if (!keyStoreContext_ctor(keyStoreCtx, KEYSTORE_IV, &masterKeyData))
    {
        Debug_LOG_ERROR("%s: Failed to initialize the keystore context!", __func__);
        return false;
    }

    err = SeosKeyStore_init(localKeyStore,
                            keyStoreCtx->fileStreamFactory,
                            *hCrypto,
                            KEY_STORE_INSTANCE_NAME);

    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosKeyStore_init failed with error code %d!", __func__,
                        err);
        return false;
    }

    return true;
}

static void deinitializeApp(OS_Crypto_Handle_t hCrypto,
                            SeosKeyStore* localKeyStore, KeyStoreContext* keyStoreCtx)
{
    OS_Crypto_free(hCrypto);
    SeosKeyStore_deInit(&(localKeyStore->parent));
    keyStoreContext_dtor(keyStoreCtx);
}

static int dummyEntropyFunc(void* ctx, unsigned char* buf, size_t len)
{
    return 0;
}

static void generateAndImportKeyPair(OS_Crypto_Handle_t hCrypto,
                                     SeosKeyStoreCtx* keyStoreCtx,
                                     char* keyNamePrv,
                                     char* keyNamePub,
                                     OS_CryptoKey_Spec_t* spec)
{
    OS_CryptoKey_Handle_t hKeyPrv;
    OS_CryptoKey_Handle_t hKeyPub;
    seos_err_t err = SEOS_ERROR_GENERIC;

    err = OS_CryptoKey_generate(&hKeyPrv, hCrypto, spec);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_CryptoKey_generate failed with err %d", err);
    err = OS_CryptoKey_makePublic(&hKeyPub, hCrypto, hKeyPrv,
                                       &spec->key.attribs);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_CryptoKey_generate failed with err %d", err);

    err = OS_CryptoKey_export(hKeyPrv, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_CryptoKey_export failed with err %d", err);
    err = SeosKeyStoreApi_importKey(keyStoreCtx, keyNamePrv, &keyData,
                                    sizeof(keyData));
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_importKey failed with err %d", err);

    err = OS_CryptoKey_export(hKeyPub, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "OS_CryptoKey_export failed with err %d", err);
    err = SeosKeyStoreApi_importKey(keyStoreCtx, keyNamePub, &keyData,
                                    sizeof(keyData));
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_importKey failed with err %d", err);
}

///@}
