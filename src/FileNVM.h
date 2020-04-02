/**
 * @addtogroup SEOS
 * @{
 *
 * @file FileNVM.h
 *
 * @brief a implementation of the LibMem/Nvm.h interface using the proxy
 *  NVM. The seos-linux proxy application provides facilities (like NVM or
 *  network sockets) that seos for one reason or another cannot provide natively
 *  . The seos-linux communication happens on a channel like a serial port.
 *
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
#pragma once

/* Includes ------------------------------------------------------------------*/

#include "LibMem/Nvm.h"


/* Exported macro ------------------------------------------------------------*/

#define FileNVM_TO_NVM(self) (&(self)->parent)

#define COMMAND_GET_SIZE    0x00
#define COMMAND_WRITE       0x01
#define COMMAND_READ        0x02


/* Exported types ------------------------------------------------------------*/

typedef struct FileNVM FileNVM;

struct FileNVM
{
    Nvm parent;
    const char* name;
    FILE *fp;
};


/* Exported constants --------------------------------------------------------*/
/* Exported functions ------------------------------------------------------- */
/**
 * @brief constructor.
 *
 * @return true if success
 *
 */
bool
FileNVM_ctor(
    FileNVM*    self,
    const char* name);
/**
 * @brief static implementation of virtual method NVM_write().
 *
 */
size_t
FileNVM_write(
    Nvm* nvm, size_t addr,
    void const* buffer,
    size_t length);
/**
 * @brief static implementation of virtual method NVM_read()
 *
 */
size_t
FileNVM_read(
    Nvm* nvm, size_t addr,
    void* buffer,
    size_t length);
/**
 * @brief static implementation of the erase method that is required
 * when working with flash
 *
 */
size_t
FileNVM_erase(
    Nvm*   nvm,
    size_t addr,
    size_t length);
/**
 * @brief static implementation of virtual method NVM_getSize()
 *
 */
size_t
FileNVM_getSize(
    Nvm* nvm);

void
FileNVM_dtor(
    Nvm* nvm);

///@}
