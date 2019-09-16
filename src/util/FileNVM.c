/*
 *  Copyright (C) 2018, Hensoldt Cyber GmbH
 */
/* Includes ------------------------------------------------------------------*/
#include "FileNVM.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


/* Private variables ---------------------------------------------------------*/

static const Nvm_Vtable FileNvm_vtable =
{
    .read       = FileNVM_read,
    .erase      = FileNVM_erase,
    .getSize    = FileNVM_getSize,
    .write      = FileNVM_write,
    .dtor       = FileNVM_dtor
};

/* Public functions ----------------------------------------------------------*/

bool FileNVM_ctor(FileNVM* self, const char* name)
{
    Debug_ASSERT_SELF(self);
    Nvm* nvm = FileNVM_TO_NVM(self);

    nvm->vtable = &FileNvm_vtable;
    self->name = name;
    self->fp = fopen(name, "rb+");

    if (self->fp == NULL)
    {
        char buffer[128*1024] = {0};
        memset(buffer, 0xff, 128*1024);
        self->fp = fopen(name, "wb");
        fwrite(buffer, sizeof(char), 128*1024, self->fp);
        fclose(self->fp);
    }

    self->fp = fopen(name, "rb+");
    if (self->fp == NULL)
    {
        return false;
    }

    return true;
}

size_t FileNVM_write(Nvm* nvm, size_t addr, void const* buffer, size_t length)
{
    FileNVM* self = (FileNVM*) nvm;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(buffer != NULL);
    size_t writtenTotal = 0;

    if(fseek(self->fp, addr, SEEK_SET))
    {
        Debug_LOG_ERROR("%s: fseek failed!", __func__);
        return 0;
    }
    writtenTotal = fwrite(buffer, sizeof(char), length, self->fp);

    return writtenTotal;
}

size_t FileNVM_read(Nvm* nvm, size_t addr, void* buffer, size_t length)
{
    FileNVM* self = (FileNVM*) nvm;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(buffer != NULL);
    size_t readTotal = 0;

    if(fseek(self->fp, addr, SEEK_SET))
    {
        Debug_LOG_ERROR("%s: fseek failed!", __func__);
        return 0;
    }
    readTotal = fread(buffer, sizeof(char), length, self->fp);

    return readTotal;
}

size_t FileNVM_erase(Nvm* nvm, size_t addr, size_t length)
{
    FileNVM* self = (FileNVM*) nvm;
    Debug_ASSERT_SELF(self);
    size_t erasedTotal = 0;

    char* buffer = (char*)malloc(length);
    memset(buffer, 0xFF, length);

    if(fseek(self->fp, addr, SEEK_SET))
    {
        Debug_LOG_ERROR("%s: fseek failed!", __func__);
        return 0;
    }
    erasedTotal = fwrite(buffer, sizeof(char), length, self->fp);

    free(buffer);

    return erasedTotal;
}

size_t FileNVM_getSize(Nvm* nvm)
{
    // not implemented
    return 0;
}

void FileNVM_dtor(Nvm* nvm)
{
    DECL_UNUSED_VAR(FileNVM * self) = (FileNVM*) nvm;
    Debug_ASSERT_SELF(self);
    fclose(self->fp);
}

