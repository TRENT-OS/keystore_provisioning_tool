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
#include "LibDebug/Debug.h"

#include "SeosKeyStore.h"
#include "SeosKeyStoreClient.h"

#include "SeosKeyStoreApi.h"
#include "SeosCryptoApi.h"

#include "KeyStoreInit.h"

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
static bool initializeApp(SeosCrypto* localCrypto, SeosKeyStore* localKeyStore,
                          KeyStoreContext* keyStoreCtx);
static void deinitializeApp(SeosCrypto* localCrypto,
                            SeosKeyStore* localKeyStore, KeyStoreContext* keyStoreCtx);
static int dummyEntropyFunc(void* ctx, unsigned char* buf, size_t len);
static void generateAndImportKeyPair(SeosCryptoCtx* cryptoCtx,
                                     SeosKeyStoreCtx* keyStoreCtx,
                                     char* keyNamePrv,
                                     char* keyNamePub,
                                     SeosCryptoKey_Spec* spec);

/* Private variables -------------------------------------------------------------------*/
static SeosCrypto_KeyHandle keyHandle;
static SeosCryptoKey_Data keyData;
static SeosCryptoKey_Spec keySpec =
{
    .type = SeosCryptoKey_SpecType_BITS
};

/* Application -------------------------------------------------------------------*/
int main(int argc, char* argv[])
{
    SeosCrypto localCrypto;
    SeosKeyStore localKeyStore;
    KeyStoreContext keyStoreCtx;

    seos_err_t err = SEOS_ERROR_GENERIC;
    unsigned int importType = atoi(argv[1]);

    unsigned int keyFlags = 0;
    unsigned int keyLenBits = 0;

    /********************************** Initialization ************************************/
    if (!initializeApp(&localCrypto, &localKeyStore, &keyStoreCtx))
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

        keyFlags = atoi(argv[3]);
        keyLenBits = atoi(argv[4]);

        char* keyBytes = argv[5];
        char* keyName = argv[2];

        if (strlen(keyBytes) == KEY_BYTES_EMPTY_STRING_LEN
            && !strncmp(keyBytes, KEY_BYTES_EMPTY_STRING, KEY_BYTES_EMPTY_STRING_LEN))
        {
            Debug_LOG_DEBUG("\nGenerating AES key:\n   key name = %s\n   key length = %u\n   key flags = %u\n\n",
                            keyName, keyLenBits, keyFlags);

            keySpec.key.type = SeosCryptoKey_Type_AES;
            keySpec.key.attribs.flags = keyFlags;
            keySpec.key.params.bits = keyLenBits;
            err = SeosCryptoApi_keyGenerate(&localCrypto.parent, &keyHandle, &keySpec);
            Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                                  "SeosCryptoApi_keyGenerate failed with err %d", err);

            err = SeosCryptoApi_keyExport(&localCrypto.parent, keyHandle, NULL, &keyData);
            Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                                  "SeosCryptoApi_keyExport failed with err %d", err);
        }
        else
        {
            Debug_LOG_DEBUG("\nImporting AES key:\n   key name = %s\n   key length = %u\n   key flags = %u\n   key bytes = %s\n\n",
                            keyName, keyLenBits, keyFlags, keyBytes);

            keyData.type = SeosCryptoKey_Type_AES;
            keyData.attribs.flags = keyFlags;
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

        keyFlags = atoi(argv[4]);
        keyLenBits = atoi(argv[5]);

        char* keyNamePrv = argv[2];
        char* keyNamePub = argv[3];

        keySpec.type = SeosCryptoKey_SpecType_BITS;
        keySpec.key.attribs.flags = keyFlags;
        keySpec.key.params.bits = keyLenBits;

        switch (importType)
        {
        case RSA_KEY_PAIR:
            Debug_LOG_DEBUG("\nGenerating RSA key pair:\n   private key name = %s\n   public key name = %s\n   key length = %u\n   key flags = %u\n\n",
                            keyNamePrv, keyNamePub, keyLenBits, keyFlags);
            keySpec.key.type = SeosCryptoKey_Type_RSA_PRV;
            break;

        case DH_KEY_PAIR:
            Debug_LOG_DEBUG("\nGenerating DH key pair:\n   private key name = %s\n   public key name = %s\n   key length = %u\n   key flags = %u\n\n",
                            keyNamePrv, keyNamePub, keyLenBits, keyFlags);
            keySpec.key.type = SeosCryptoKey_Type_DH_PRV;
            break;

        case SECP256R1_KEY_PAIR:
            Debug_LOG_DEBUG("\nGenerating SECP256r1 key pair:\n   private key name = %s\n   public key name = %s\n   key length = %u\n   key flags = %u\n\n",
                            keyNamePrv, keyNamePub, keyLenBits, keyFlags);
            keySpec.key.type = SeosCryptoKey_Type_SECP256R1_PRV;
            break;

        default:
            Debug_LOG_ERROR("\n\nInvalid import type %u!\n\n\n\n", importType);
            break;
        }

        generateAndImportKeyPair(&localCrypto.parent,
                                 &(localKeyStore.parent),
                                 keyNamePrv,
                                 keyNamePub,
                                 &keySpec);
    }

exit:
    deinitializeApp(&localCrypto, &localKeyStore, &keyStoreCtx);

    return 0;
}

/* Private functions -------------------------------------------------------------------*/
static bool initializeApp(SeosCrypto* localCrypto, SeosKeyStore* localKeyStore,
                          KeyStoreContext* keyStoreCtx)
{
    const SeosCrypto_Callbacks cb =
    {
        .malloc     = malloc,
        .free       = free,
        .entropy    = dummyEntropyFunc
    };
    seos_err_t err = SeosCrypto_init(localCrypto, &cb, NULL);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCrypto_init failed with error code %d!", __func__,
                        err);
        return false;
    }

    if (!keyStoreContext_ctor(keyStoreCtx))
    {
        Debug_LOG_ERROR("%s: Failed to initialize the test!", __func__);
        return false;
    }

    err = SeosKeyStore_init(localKeyStore,
                            keyStoreCtx->fileStreamFactory,
                            localCrypto,
                            KEY_STORE_INSTANCE_NAME);

    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosKeyStore_init failed with error code %d!", __func__,
                        err);
        return false;
    }

    return true;
}

static void deinitializeApp(SeosCrypto* localCrypto,
                            SeosKeyStore* localKeyStore, KeyStoreContext* keyStoreCtx)
{
    SeosCrypto_free(&(localCrypto->parent));
    SeosKeyStore_deInit(&(localKeyStore->parent));
    keyStoreContext_dtor(keyStoreCtx);
}

static int dummyEntropyFunc(void* ctx, unsigned char* buf, size_t len)
{
    return 0;
}

static void generateAndImportKeyPair(SeosCryptoCtx* cryptoCtx,
                                     SeosKeyStoreCtx* keyStoreCtx,
                                     char* keyNamePrv,
                                     char* keyNamePub,
                                     SeosCryptoKey_Spec* spec)
{
    SeosCrypto_KeyHandle keyHandlePrv;
    SeosCrypto_KeyHandle keyHandlePub;
    seos_err_t err = SEOS_ERROR_GENERIC;

    err = SeosCryptoApi_keyGenerate(cryptoCtx, &keyHandlePrv, spec);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyGenerate failed with err %d", err);
    err = SeosCryptoApi_keyMakePublic(cryptoCtx, &keyHandlePub, keyHandlePrv,
                                      &spec->key.attribs);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyGenerate failed with err %d", err);

    err = SeosCryptoApi_keyExport(cryptoCtx, keyHandlePrv, NULL,  &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyExport failed with err %d", err);
    err = SeosKeyStoreApi_importKey(keyStoreCtx, keyNamePrv, &keyData,
                                    sizeof(keyData));
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_importKey failed with err %d", err);

    err = SeosCryptoApi_keyExport(cryptoCtx, keyHandlePub, NULL, &keyData);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosCryptoApi_keyExport failed with err %d", err);
    err = SeosKeyStoreApi_importKey(keyStoreCtx, keyNamePub, &keyData,
                                    sizeof(keyData));
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS,
                          "SeosKeyStoreApi_importKey failed with err %d", err);
}

///@}