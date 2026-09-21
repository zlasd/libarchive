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
#include "archive_hmac_private.h"
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
	return (__archive_rar5_derive_keys(password, salt, kdf_count, key,
	    NULL, NULL));
}

struct rar5_hmac_sha256_templates {
	archive_sha256_ctx inner;
	archive_sha256_ctx outer;
	int inner_valid;
	int outer_valid;
};

/* PBKDF2 repeats HMAC with the same password.  Keep the SHA-256 state after
 * hashing the inner and outer pads so every round only hashes its 32-byte
 * input, matching the optimization used by the reference RAR decoder. */

static void
rar5_hmac_sha256_templates_cleanup(
    struct rar5_hmac_sha256_templates *templates)
{
	uint8_t digest[32];

	if (templates->inner_valid)
		(void)archive_sha256_final(&templates->inner, digest);
	if (templates->outer_valid)
		(void)archive_sha256_final(&templates->outer, digest);
	__archive_cryptor_secure_zero(templates, sizeof(*templates));
	__archive_cryptor_secure_zero(digest, sizeof(digest));
}

static int
rar5_hmac_sha256_templates_init(struct rar5_hmac_sha256_templates *templates,
    const uint8_t *password, size_t password_len)
{
	archive_sha256_ctx ctx;
	uint8_t key[64], digest[32];
	const uint8_t *normalized_password = password;
	size_t normalized_len = password_len;
	int ctx_valid = 0, r = CRYPTOR_STUB_FUNCTION;
	unsigned i;

	memset(templates, 0, sizeof(*templates));
	memset(key, 0, sizeof(key));
	memset(digest, 0, sizeof(digest));
	if (password_len > sizeof(key)) {
		if (archive_sha256_init(&ctx) != ARCHIVE_OK)
			goto cleanup;
		ctx_valid = 1;
		if (archive_sha256_update(&ctx, password, password_len) !=
		    ARCHIVE_OK)
			goto cleanup;
		ctx_valid = 0;
		if (archive_sha256_final(&ctx, digest) != ARCHIVE_OK)
			goto cleanup;
		normalized_password = digest;
		normalized_len = sizeof(digest);
	}
	if (normalized_len != 0)
		memcpy(key, normalized_password, normalized_len);
	for (i = 0; i < sizeof(key); i++)
		key[i] ^= 0x36;
	if (archive_sha256_init(&templates->inner) != ARCHIVE_OK)
		goto cleanup;
	templates->inner_valid = 1;
	if (archive_sha256_update(&templates->inner, key, sizeof(key)) !=
	    ARCHIVE_OK)
		goto cleanup;
	for (i = 0; i < sizeof(key); i++)
		key[i] ^= 0x36 ^ 0x5c;
	if (archive_sha256_init(&templates->outer) != ARCHIVE_OK)
		goto cleanup;
	templates->outer_valid = 1;
	if (archive_sha256_update(&templates->outer, key, sizeof(key)) !=
	    ARCHIVE_OK)
		goto cleanup;
	r = 0;

cleanup:
	if (ctx_valid)
		(void)archive_sha256_final(&ctx, digest);
	__archive_cryptor_secure_zero(key, sizeof(key));
	__archive_cryptor_secure_zero(digest, sizeof(digest));
	if (r != 0)
		rar5_hmac_sha256_templates_cleanup(templates);
	return (r);
}

static int
rar5_hmac_sha256_calculate(
    const struct rar5_hmac_sha256_templates *templates,
    const uint8_t *data, size_t data_len, uint8_t digest[32])
{
	archive_sha256_ctx inner, outer;
	uint8_t inner_digest[32];
	int inner_valid = 0, outer_valid = 0, r = CRYPTOR_STUB_FUNCTION;

	if (archive_sha256_clone(&inner, &templates->inner) != ARCHIVE_OK)
		goto cleanup;
	inner_valid = 1;
	if (archive_sha256_update(&inner, data, data_len) != ARCHIVE_OK)
		goto cleanup;
	inner_valid = 0;
	if (archive_sha256_final(&inner, inner_digest) != ARCHIVE_OK)
		goto cleanup;
	if (archive_sha256_clone(&outer, &templates->outer) != ARCHIVE_OK)
		goto cleanup;
	outer_valid = 1;
	if (archive_sha256_update(&outer, inner_digest,
	    sizeof(inner_digest)) != ARCHIVE_OK)
		goto cleanup;
	outer_valid = 0;
	if (archive_sha256_final(&outer, digest) != ARCHIVE_OK)
		goto cleanup;
	r = 0;

cleanup:
	if (inner_valid)
		(void)archive_sha256_final(&inner, inner_digest);
	if (outer_valid)
		(void)archive_sha256_final(&outer, inner_digest);
	__archive_cryptor_secure_zero(inner_digest, sizeof(inner_digest));
	return (r);
}

static int
rar5_pbkdf2_sha256(const char *password, const uint8_t *salt,
    unsigned rounds, uint8_t key[ARCHIVE_RAR5_KEY_SIZE],
    uint8_t hash_key[ARCHIVE_RAR5_HASH_KEY_SIZE],
    uint8_t verification[32])
{
	struct rar5_hmac_sha256_templates templates;
	uint8_t salt_data[ARCHIVE_RAR5_SALT_SIZE + 4];
	uint8_t u[32], value[32];
	unsigned current, final_rounds;
	size_t i;
	int r;

	memcpy(salt_data, salt, ARCHIVE_RAR5_SALT_SIZE);
	salt_data[ARCHIVE_RAR5_SALT_SIZE] = 0;
	salt_data[ARCHIVE_RAR5_SALT_SIZE + 1] = 0;
	salt_data[ARCHIVE_RAR5_SALT_SIZE + 2] = 0;
	salt_data[ARCHIVE_RAR5_SALT_SIZE + 3] = 1;
	r = rar5_hmac_sha256_templates_init(&templates,
	    (const uint8_t *)password, strlen(password));
	if (r != 0)
		goto cleanup;
	r = rar5_hmac_sha256_calculate(&templates, salt_data,
	    sizeof(salt_data), u);
	if (r != 0)
		goto cleanup_templates;
	memcpy(value, u, sizeof(value));
	if (rounds == 1)
		memcpy(key, value, ARCHIVE_RAR5_KEY_SIZE);
	/* RAR5 derives all three values from one continued PBKDF2 chain. */
	final_rounds = rounds + (verification != NULL ? 32 :
	    hash_key != NULL ? 16 : 0);
	for (current = 2; current <= final_rounds; current++) {
		r = rar5_hmac_sha256_calculate(&templates, u, sizeof(u), u);
		if (r != 0)
			goto cleanup_templates;
		for (i = 0; i < sizeof(value); i++)
			value[i] ^= u[i];
		if (current == rounds)
			memcpy(key, value, ARCHIVE_RAR5_KEY_SIZE);
		if (hash_key != NULL && current == rounds + 16)
			memcpy(hash_key, value, ARCHIVE_RAR5_HASH_KEY_SIZE);
		if (verification != NULL && current == rounds + 32)
			memcpy(verification, value, 32);
	}
	r = 0;

cleanup_templates:
	rar5_hmac_sha256_templates_cleanup(&templates);
cleanup:
	__archive_cryptor_secure_zero(salt_data, sizeof(salt_data));
	__archive_cryptor_secure_zero(u, sizeof(u));
	__archive_cryptor_secure_zero(value, sizeof(value));
	return (r);
}

int
__archive_rar5_derive_keys(const char *password, const uint8_t *salt,
    unsigned kdf_count, uint8_t key[ARCHIVE_RAR5_KEY_SIZE],
    uint8_t hash_key[ARCHIVE_RAR5_HASH_KEY_SIZE],
    uint8_t password_check[ARCHIVE_RAR5_PASSWORD_CHECK_SIZE])
{
	uint64_t rounds;
	uint8_t verification[32];
	size_t i;
	int r;

	if (password == NULL || salt == NULL || key == NULL ||
	    kdf_count > ARCHIVE_RAR5_MAX_KDF_COUNT)
		return (-1);
	rounds = UINT64_C(1) << kdf_count;
	if (rounds > UINT_MAX - 32)
		return (-1);
	r = rar5_pbkdf2_sha256(password, salt, (unsigned)rounds, key,
	    hash_key, password_check != NULL ? verification : NULL);
	if (r == 0)
		goto fold_password_check;
	__archive_cryptor_secure_zero(key, ARCHIVE_RAR5_KEY_SIZE);
	if (hash_key != NULL)
		__archive_cryptor_secure_zero(hash_key,
		    ARCHIVE_RAR5_HASH_KEY_SIZE);
	__archive_cryptor_secure_zero(verification, sizeof(verification));
	r = archive_pbkdf2_sha256(password, strlen(password), salt,
	    ARCHIVE_RAR5_SALT_SIZE, (unsigned)rounds, key,
	    ARCHIVE_RAR5_KEY_SIZE);
	if (r != 0)
		goto failed;
	if (hash_key != NULL) {
		r = archive_pbkdf2_sha256(password, strlen(password), salt,
		    ARCHIVE_RAR5_SALT_SIZE, (unsigned)rounds + 16, hash_key,
		    ARCHIVE_RAR5_HASH_KEY_SIZE);
		if (r != 0)
			goto failed;
	}
	if (password_check != NULL) {
		r = archive_pbkdf2_sha256(password, strlen(password), salt,
		    ARCHIVE_RAR5_SALT_SIZE, (unsigned)rounds + 32,
		    verification, sizeof(verification));
		if (r != 0)
			goto failed;
	}

fold_password_check:
	if (password_check != NULL) {
		memset(password_check, 0, ARCHIVE_RAR5_PASSWORD_CHECK_SIZE);
		for (i = 0; i < sizeof(verification); i++)
			password_check[i % ARCHIVE_RAR5_PASSWORD_CHECK_SIZE] ^=
			    verification[i];
	}
	__archive_cryptor_secure_zero(verification, sizeof(verification));
	return (0);

failed:
	__archive_cryptor_secure_zero(key, ARCHIVE_RAR5_KEY_SIZE);
	if (hash_key != NULL)
		__archive_cryptor_secure_zero(hash_key,
		    ARCHIVE_RAR5_HASH_KEY_SIZE);
	if (password_check != NULL)
		__archive_cryptor_secure_zero(password_check,
		    ARCHIVE_RAR5_PASSWORD_CHECK_SIZE);
	__archive_cryptor_secure_zero(verification, sizeof(verification));
	return (r);
}

int
__archive_rar5_derive_keys_cached(struct archive_rar5_kdf_cache *cache,
    const char *password, const uint8_t *salt, unsigned kdf_count,
    uint8_t key[ARCHIVE_RAR5_KEY_SIZE],
    uint8_t hash_key[ARCHIVE_RAR5_HASH_KEY_SIZE],
    uint8_t password_check[ARCHIVE_RAR5_PASSWORD_CHECK_SIZE])
{
	archive_sha256_ctx ctx;
	struct archive_rar5_kdf_cache_entry *entry;
	uint8_t password_tag[32], derived_key[ARCHIVE_RAR5_KEY_SIZE];
	uint8_t derived_hash_key[ARCHIVE_RAR5_HASH_KEY_SIZE];
	uint8_t derived_password_check[ARCHIVE_RAR5_PASSWORD_CHECK_SIZE];
	uint8_t kdf_tag;
	size_t i;
	int r;

	/* The caller owns this small cache for one archive reader and clears it
	 * on cleanup, so derived keys never become global or cross threads. */
	if (cache == NULL)
		return (__archive_rar5_derive_keys(password, salt, kdf_count,
		    key, hash_key, password_check));
	if (password == NULL || salt == NULL || key == NULL)
		return (-1);
	kdf_tag = (uint8_t)kdf_count;
	if (archive_sha256_init(&ctx) != ARCHIVE_OK)
		return (__archive_rar5_derive_keys(password, salt, kdf_count,
		    key, hash_key, password_check));
	if (archive_sha256_update(&ctx, password, strlen(password)) !=
	    ARCHIVE_OK || archive_sha256_update(&ctx, salt,
	    ARCHIVE_RAR5_SALT_SIZE) != ARCHIVE_OK ||
	    archive_sha256_update(&ctx, &kdf_tag, sizeof(kdf_tag)) !=
	    ARCHIVE_OK) {
		(void)archive_sha256_final(&ctx, password_tag);
		__archive_cryptor_secure_zero(password_tag,
		    sizeof(password_tag));
		return (__archive_rar5_derive_keys(password, salt, kdf_count,
		    key, hash_key, password_check));
	}
	if (archive_sha256_final(&ctx, password_tag) != ARCHIVE_OK) {
		__archive_cryptor_secure_zero(password_tag,
		    sizeof(password_tag));
		return (__archive_rar5_derive_keys(password, salt, kdf_count,
		    key, hash_key, password_check));
	}
	for (i = 0; i < ARCHIVE_RAR5_KDF_CACHE_SIZE; i++) {
		entry = &cache->entries[i];
		if (entry->valid && entry->kdf_count == kdf_count &&
		    __archive_cryptor_constant_time_equal(entry->password_tag,
		    password_tag, sizeof(password_tag)) &&
		    __archive_cryptor_constant_time_equal(entry->salt, salt,
		    ARCHIVE_RAR5_SALT_SIZE)) {
			memcpy(key, entry->key, ARCHIVE_RAR5_KEY_SIZE);
			if (hash_key != NULL)
				memcpy(hash_key, entry->hash_key,
				    ARCHIVE_RAR5_HASH_KEY_SIZE);
			if (password_check != NULL)
				memcpy(password_check, entry->password_check,
				    ARCHIVE_RAR5_PASSWORD_CHECK_SIZE);
			__archive_cryptor_secure_zero(password_tag,
			    sizeof(password_tag));
			return (0);
		}
	}
	r = __archive_rar5_derive_keys(password, salt, kdf_count, derived_key,
	    derived_hash_key, derived_password_check);
	if (r != 0)
		goto cleanup;
	entry = &cache->entries[cache->next % ARCHIVE_RAR5_KDF_CACHE_SIZE];
	cache->next++;
	__archive_cryptor_secure_zero(entry, sizeof(*entry));
	memcpy(entry->password_tag, password_tag,
	    sizeof(entry->password_tag));
	memcpy(entry->salt, salt, sizeof(entry->salt));
	memcpy(entry->key, derived_key, sizeof(entry->key));
	memcpy(entry->hash_key, derived_hash_key, sizeof(entry->hash_key));
	memcpy(entry->password_check, derived_password_check,
	    sizeof(entry->password_check));
	entry->kdf_count = kdf_count;
	entry->valid = 1;
	memcpy(key, derived_key, ARCHIVE_RAR5_KEY_SIZE);
	if (hash_key != NULL)
		memcpy(hash_key, derived_hash_key, ARCHIVE_RAR5_HASH_KEY_SIZE);
	if (password_check != NULL)
		memcpy(password_check, derived_password_check,
		    ARCHIVE_RAR5_PASSWORD_CHECK_SIZE);

cleanup:
	__archive_cryptor_secure_zero(password_tag, sizeof(password_tag));
	__archive_cryptor_secure_zero(derived_key, sizeof(derived_key));
	__archive_cryptor_secure_zero(derived_hash_key,
	    sizeof(derived_hash_key));
	__archive_cryptor_secure_zero(derived_password_check,
	    sizeof(derived_password_check));
	return (r);
}

void
__archive_rar5_kdf_cache_clear(struct archive_rar5_kdf_cache *cache)
{
	if (cache != NULL)
		__archive_cryptor_secure_zero(cache, sizeof(*cache));
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

static int
rar5_hmac_sha256(const uint8_t key[ARCHIVE_RAR5_HASH_KEY_SIZE],
    const uint8_t *data, size_t data_size, uint8_t digest[32])
{
	archive_hmac_sha256_ctx ctx;
	size_t digest_size = 32;

	if (key == NULL || data == NULL || digest == NULL ||
	    archive_hmac_sha256_init(&ctx, key,
	    ARCHIVE_RAR5_HASH_KEY_SIZE) != 0)
		return (-1);
	archive_hmac_sha256_update(&ctx, data, data_size);
	archive_hmac_sha256_final(&ctx, digest, &digest_size);
	archive_hmac_sha256_cleanup(&ctx);
	return (digest_size == 32 ? 0 : -1);
}

int
__archive_rar5_mac_crc32(
    const uint8_t hash_key[ARCHIVE_RAR5_HASH_KEY_SIZE], uint32_t crc,
    uint32_t *mac)
{
	uint8_t raw_crc[4], digest[32];
	size_t i;

	if (mac == NULL)
		return (-1);
	raw_crc[0] = (uint8_t)crc;
	raw_crc[1] = (uint8_t)(crc >> 8);
	raw_crc[2] = (uint8_t)(crc >> 16);
	raw_crc[3] = (uint8_t)(crc >> 24);
	if (rar5_hmac_sha256(hash_key, raw_crc, sizeof(raw_crc), digest) != 0)
		return (-1);
	*mac = 0;
	for (i = 0; i < sizeof(digest); i++)
		*mac ^= (uint32_t)digest[i] << ((i & 3) * 8);
	__archive_cryptor_secure_zero(digest, sizeof(digest));
	return (0);
}

int
__archive_rar5_mac_blake2(
    const uint8_t hash_key[ARCHIVE_RAR5_HASH_KEY_SIZE],
    const uint8_t blake2[32], uint8_t mac[32])
{
	return (rar5_hmac_sha256(hash_key, blake2, 32, mac));
}
