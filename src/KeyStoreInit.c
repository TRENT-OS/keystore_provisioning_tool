/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
/* Includes ------------------------------------------------------------------*/
#include "KeyStoreInit.h"

/* Defines -------------------------------------------------------------------*/
#define NVM_PARTITION_SIZE      (1024*128)
#define NVM_PARTITION_NAME      "nvm_06"

/* Public functions -----------------------------------------------------------*/
bool keyStoreContext_ctor(
    KeyStoreContext*           keyStoreCtx,
    const void*                startIv,
    const OS_CryptoKey_Data_t* masterKeyData)
{
    // create and initialize an nvm instance that writes directly to a file
    if (!FileNVM_ctor(&(keyStoreCtx->fileNvm), NVM_PARTITION_NAME))
    {
        Debug_LOG_ERROR("%s: Failed to initialize FileNVM!", __func__);
        return false;
    }

    if (!AesNvm_ctor(&(keyStoreCtx->aesNvm),
                     FileNVM_TO_NVM(&(keyStoreCtx->fileNvm)),
                     startIv,
                     masterKeyData))
    {
        Debug_LOG_ERROR("%s: Failed to initialize AesNvm!", __func__);
        return false;
    }

    if (!SeosSpiffs_ctor(&(keyStoreCtx->fs), AesNvm_TO_NVM(&(keyStoreCtx->aesNvm)),
                         NVM_PARTITION_SIZE, 0))
    {
        Debug_LOG_ERROR("%s: Failed to initialize spiffs!", __func__);
        return false;
    }

    seos_err_t ret = SeosSpiffs_mount(&(keyStoreCtx->fs));
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: spiffs mount failed with error code %d!",
                        __func__, ret);

        return false;
    }

    keyStoreCtx->fileStreamFactory = SpiffsFileStreamFactory_TO_FILE_STREAM_FACTORY(
                                         SpiffsFileStreamFactory_getInstance(&(keyStoreCtx->fs)));
    if (keyStoreCtx->fileStreamFactory == NULL)
    {
        Debug_LOG_ERROR("%s: Failed to get the SpiffsFileStreamFactory instance!",
                        __func__);
        return false;
    }

    return true;
}

bool keyStoreContext_dtor(KeyStoreContext* keyStoreCtx)
{
    FileNVM_dtor(FileNVM_TO_NVM(&(keyStoreCtx->fileNvm)));
    SeosSpiffs_dtor(&(keyStoreCtx->fs));
    FileStreamFactory_dtor(keyStoreCtx->fileStreamFactory);

    return true;
}
