/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#include "AesNvm.h"
#include "FileNVM.h"
#include "SeosSpiffs.h"
#include "SpiffsFileStream.h"
#include "SpiffsFileStreamFactory.h"
#include "SeosKeyStore.h"

typedef struct KeyStoreContext
{
    FileNVM fileNvm;
    AesNvm aesNvm;
    SeosSpiffs fs;
    FileStreamFactory* fileStreamFactory;
    SeosKeyStore keyStore;
} KeyStoreContext;


bool
keyStoreContext_ctor(
    KeyStoreContext*            keyStoreCtx,
    const void*                 startIv,
    const OS_CryptoKey_Data_t*  masterKeyData);


bool
keyStoreContext_dtor(
    KeyStoreContext* keyStoreCtx);
