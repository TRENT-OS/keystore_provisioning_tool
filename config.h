/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * SEOS libraries configurations
 *
 */
#pragma once


//-----------------------------------------------------------------------------
// Debug
//-----------------------------------------------------------------------------

#if !defined(NDEBUG)
#   define Debug_Config_STANDARD_ASSERT
#   define Debug_Config_ASSERT_SELF_PTR
#else
#   define Debug_Config_DISABLE_ASSERT
#   define Debug_Config_NO_ASSERT_SELF_PTR
#endif

#define Debug_Config_LOG_LEVEL              Debug_LOG_LEVEL_DEBUG
#define Debug_Config_INCLUDE_LEVEL_IN_MSG
#define Debug_Config_LOG_WITH_FILE_LINE


//-----------------------------------------------------------------------------
// Memory
//-----------------------------------------------------------------------------

#define Memory_Config_USE_STDLIB_ALLOC

//-----------------------------------------------------------------------------
// Keystore
//-----------------------------------------------------------------------------

#define KEY_INT_PROPERTY_LEN    4       /* Used to initialize the buffers for serialization of the size_t type
                                        key properties - it represents the number of bytes that size_t type
                                        takes up in memory */

#define MAX_KEY_LEN             2048    /* Maximum length of the raw key in bytes */
#define MAX_KEY_NAME_LEN        16      /* Maximum length of the key name (including the null char) */

#define KEYSTORE_IV             "15e1f594c54670bf"
#define KEYSTORE_KEY_AES        "f131830db44c54742fc3f3265f0f1a0c"
