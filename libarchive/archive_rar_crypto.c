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

#include "archive_platform.h"

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "archive.h"
#include "archive_cryptor_private.h"
#include "archive_digest_private.h"
#include "archive_rar_crypto_private.h"

int
__archive_rar5_derive_key(const char *password, const uint8_t *salt,
    unsigned kdf_count, uint8_t key[ARCHIVE_RAR5_KEY_SIZE])
{
	uint64_t rounds;

	if (password == NULL || salt == NULL || key == NULL ||
	    kdf_count > ARCHIVE_RAR5_MAX_KDF_COUNT)
		return (-1);
	rounds = UINT64_C(1) << kdf_count;
	if (rounds > UINT_MAX)
		return (-1);
	return (archive_pbkdf2_sha256(password, strlen(password), salt,
	    ARCHIVE_RAR5_SALT_SIZE, (unsigned)rounds, key,
	    ARCHIVE_RAR5_KEY_SIZE));
}

int
__archive_rar5_check_value_is_valid(
    const uint8_t check[ARCHIVE_RAR5_CHECK_SIZE])
{
	archive_sha256_ctx ctx;
	uint8_t digest[32];
	int valid;

	if (check == NULL || archive_sha256_init(&ctx) != ARCHIVE_OK)
		return (0);
	if (archive_sha256_update(&ctx, check, 8) != ARCHIVE_OK ||
	    archive_sha256_final(&ctx, digest) != ARCHIVE_OK) {
		__archive_cryptor_secure_zero(digest, sizeof(digest));
		return (0);
	}
	valid = __archive_cryptor_constant_time_equal(digest, check + 8, 4);
	__archive_cryptor_secure_zero(digest, sizeof(digest));
	return (valid);
}
