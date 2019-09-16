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

#include "KeyStoreInit.h"

/* Defines -------------------------------------------------------------------*/
#define NVM_CHANNEL_NUMBER      (6)
#define KEY_STORE_INSTANCE_NAME "KeyStore1"

/* Macros -------------------------------------------------------------------*/
#define LEN_BITS_TO_BYTES(lenBits)  (lenBits / CHAR_BIT + ((lenBits % CHAR_BIT) ? 1 : 0))

/* Private function prototypes -------------------------------------------------------------------*/
static bool initializeApp(SeosCrypto* cryptoApi, SeosKeyStore* localKeyStore, KeyStoreContext* keyStoreCtx);
static void deinitializeApp(SeosCrypto* cryptoApi, SeosKeyStore* localKeyStore, KeyStoreContext* keyStoreCtx);

int main(int argc, char *argv[])
{
    SeosCrypto cryptoCtx;
    KeyStoreContext keyStoreCtx;
    SeosKeyStore localKeyStore;
    SeosCrypto_KeyHandle key;
    bool generateKey = true;
    seos_err_t err = SEOS_ERROR_GENERIC;

    unsigned int algorithm;
    unsigned int flags;
    size_t lenBits;

    if(argc == 5)
    {
        Debug_LOG_INFO("\nGenerating key...\n");
    }
    else if(argc == 6)
    {
        Debug_LOG_INFO("\nImporting key...\n");
        generateKey = false;
    }
    else
    {
        Debug_LOG_INFO("\n%d is an invalid number of arguments! Expecting:\n   Generate key => $keyName $algorithm $flags $lenBits\n   Import key => $keyName $algorithm $flags $lenBits $keyBytes", argc);
        return 0;
    }

    if(!initializeApp(&cryptoCtx, &localKeyStore, &keyStoreCtx))
    {
        Debug_LOG_ERROR("\n\nFailed to initialize the provisioning tool!\n\n\n\n");
        return 0;
    }

    algorithm = atoi(argv[2]);
    flags = atoi(argv[3]);
    lenBits = atoi(argv[4]);

    if(generateKey)
    {
        err = SeosKeyStoreApi_generateKey(&(localKeyStore.parent),
                                          &key,
                                          argv[1],
                                          algorithm,
                                          flags,
                                          lenBits);
        if (err != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: SeosKeyStoreApi_generateKey failed with error code %d!",
                            __func__, err);
            return 0;
        }
    }
    else
    {
        err = SeosKeyStoreApi_importKey(&(localKeyStore.parent),
                                        &key,
                                        argv[1],
                                        argv[5],
                                        algorithm,
                                        flags,
                                        lenBits);
        if (err != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: SeosKeyStoreApi_importKey failed with error code %d!",
                            __func__, err);
            return 0;
        }
    }
    
    deinitializeApp(&cryptoCtx, &localKeyStore, &keyStoreCtx);

    return 0;
}

/* Private functions -------------------------------------------------------------------*/
static bool initializeApp(SeosCrypto* cryptoApi, SeosKeyStore* localKeyStore, KeyStoreContext* keyStoreCtx)
{
    seos_err_t err = SeosCrypto_init(cryptoApi, malloc, free, NULL, NULL);
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
                            cryptoApi,
                            KEY_STORE_INSTANCE_NAME);

    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosKeyStore_init failed with error code %d!", __func__,
                        err);
        return false;
    }

    return true;
}

static void deinitializeApp(SeosCrypto* cryptoApi, SeosKeyStore* localKeyStore, KeyStoreContext* keyStoreCtx)
{
    SeosCrypto_deInit(&(cryptoApi->parent));
    SeosKeyStore_deInit(&(localKeyStore->parent));
    keyStoreContext_dtor(keyStoreCtx);
}

///@}
