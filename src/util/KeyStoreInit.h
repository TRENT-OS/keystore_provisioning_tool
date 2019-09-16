/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */

#include "External.h"

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

bool keyStoreContext_ctor(KeyStoreContext* keyStoreCtx);
bool keyStoreContext_dtor(KeyStoreContext* keyStoreCtx);