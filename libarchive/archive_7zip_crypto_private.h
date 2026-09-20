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

#ifndef ARCHIVE_7ZIP_CRYPTO_PRIVATE_H_INCLUDED
#define ARCHIVE_7ZIP_CRYPTO_PRIVATE_H_INCLUDED

#ifndef __LIBARCHIVE_BUILD
#error This header is only to be used internally to libarchive.
#endif

#include <stddef.h>
#include <stdint.h>

#define ARCHIVE_7ZIP_AES_KEY_SIZE 32
#define ARCHIVE_7ZIP_AES_BLOCK_SIZE 16
#define ARCHIVE_7ZIP_AES_MAX_CYCLES_POWER 24

struct archive_7zip_aes_properties {
	unsigned cycles_power;
	size_t salt_len;
	size_t iv_len;
	uint8_t salt[ARCHIVE_7ZIP_AES_BLOCK_SIZE];
	uint8_t iv[ARCHIVE_7ZIP_AES_BLOCK_SIZE];
};

int __archive_7zip_aes_parse_properties(const uint8_t *, size_t,
    struct archive_7zip_aes_properties *);
int __archive_7zip_password_utf16le(const char *, uint8_t **, size_t *);
int __archive_7zip_aes_derive_key(
    const struct archive_7zip_aes_properties *, const uint8_t *, size_t,
    uint8_t [ARCHIVE_7ZIP_AES_KEY_SIZE]);

#endif
