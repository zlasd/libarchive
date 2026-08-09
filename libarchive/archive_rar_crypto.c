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
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "archive.h"
#include "archive_cryptor_private.h"
#include "archive_digest_private.h"
#include "archive_rar_crypto_private.h"

int
__archive_rar3_derive_key(const char *password, const uint8_t *salt,
    size_t salt_len, uint8_t key[ARCHIVE_RAR3_KEY_SIZE],
    uint8_t iv[ARCHIVE_RAR3_IV_SIZE])
{
	archive_sha1_ctx ctx, snapshot;
	uint8_t *utf16 = NULL, *seed = NULL;
	uint8_t digest[20], counter[3];
	size_t utf16_len = 0, seed_len;
	unsigned i, j;
	int r = -1, ctx_valid = 0;

	if (password == NULL || (salt == NULL && salt_len != 0) ||
	    (salt_len != 0 && salt_len != ARCHIVE_RAR3_SALT_SIZE) ||
	    key == NULL || iv == NULL)
		return (-1);
	memset(key, 0, ARCHIVE_RAR3_KEY_SIZE);
	memset(iv, 0, ARCHIVE_RAR3_IV_SIZE);
	if (__archive_cryptor_utf8_to_utf16le(password, &utf16,
	    &utf16_len) != 0 || utf16_len > SIZE_MAX - salt_len)
		goto cleanup;
	seed_len = utf16_len + salt_len;
	seed = malloc(seed_len == 0 ? 1 : seed_len);
	if (seed == NULL)
		goto cleanup;
	if (utf16_len != 0)
		memcpy(seed, utf16, utf16_len);
	if (salt_len != 0)
		memcpy(seed + utf16_len, salt, salt_len);

	if (archive_sha1_init(&ctx) != ARCHIVE_OK)
		goto cleanup;
	ctx_valid = 1;
	for (i = 0; i < UINT32_C(0x40000); i++) {
		counter[0] = (uint8_t)i;
		counter[1] = (uint8_t)(i >> 8);
		counter[2] = (uint8_t)(i >> 16);
		if (archive_sha1_update(&ctx, seed, seed_len) != ARCHIVE_OK ||
		    archive_sha1_update(&ctx, counter, sizeof(counter)) !=
		    ARCHIVE_OK)
			goto cleanup;
		if ((i & UINT32_C(0x3fff)) == 0) {
			if (archive_sha1_clone(&snapshot, &ctx) != ARCHIVE_OK) {
				r = CRYPTOR_STUB_FUNCTION;
				goto cleanup;
			}
			if (archive_sha1_final(&snapshot, digest) != ARCHIVE_OK)
				goto cleanup;
			iv[i >> 14] = digest[19];
		}
	}
	if (archive_sha1_final(&ctx, digest) != ARCHIVE_OK)
		goto cleanup;
	ctx_valid = 0;
	for (i = 0; i < ARCHIVE_RAR3_KEY_SIZE; i += 4)
		for (j = 0; j < 4; j++)
			key[i + j] = digest[i + 3 - j];
	r = 0;

cleanup:
	if (ctx_valid)
		(void)archive_sha1_final(&ctx, digest);
	__archive_cryptor_secure_zero(digest, sizeof(digest));
	__archive_cryptor_secure_zero(counter, sizeof(counter));
	if (seed != NULL)
		__archive_cryptor_secure_zero(seed, seed_len);
	free(seed);
	if (utf16 != NULL)
		__archive_cryptor_secure_zero(utf16, utf16_len);
	free(utf16);
	return (r);
}

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
