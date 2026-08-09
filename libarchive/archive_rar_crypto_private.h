/*-
 * Copyright (c) 2026 zlasd
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 */

#ifndef ARCHIVE_RAR_CRYPTO_PRIVATE_H_INCLUDED
#define ARCHIVE_RAR_CRYPTO_PRIVATE_H_INCLUDED

#ifndef __LIBARCHIVE_BUILD
#error This header is only to be used internally to libarchive.
#endif

#include <stddef.h>
#include <stdint.h>

#define ARCHIVE_RAR3_KEY_SIZE 16
#define ARCHIVE_RAR3_SALT_SIZE 8
#define ARCHIVE_RAR3_IV_SIZE 16
#define ARCHIVE_RAR5_KEY_SIZE 32
#define ARCHIVE_RAR5_SALT_SIZE 16
#define ARCHIVE_RAR5_IV_SIZE 16
#define ARCHIVE_RAR5_CHECK_SIZE 12
#define ARCHIVE_RAR5_MAX_KDF_COUNT 24

int __archive_rar3_derive_key(const char *, const uint8_t *, size_t,
    uint8_t [ARCHIVE_RAR3_KEY_SIZE], uint8_t [ARCHIVE_RAR3_IV_SIZE]);
int __archive_rar5_derive_key(const char *, const uint8_t *, unsigned,
    uint8_t [ARCHIVE_RAR5_KEY_SIZE]);
int __archive_rar5_check_value_is_valid(
    const uint8_t [ARCHIVE_RAR5_CHECK_SIZE]);

#endif
