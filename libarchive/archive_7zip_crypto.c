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

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "archive.h"
#include "archive_7zip_crypto_private.h"
#include "archive_cryptor_private.h"
#include "archive_digest_private.h"

int
__archive_7zip_aes_parse_properties(const uint8_t *data, size_t data_len,
    struct archive_7zip_aes_properties *properties)
{
	size_t salt_len, iv_len;

	if (data == NULL || properties == NULL || data_len < 1)
		return (-1);

	memset(properties, 0, sizeof(*properties));
	properties->cycles_power = data[0] & 0x3f;
	if ((data[0] & 0xc0) == 0)
		return (data_len == 1 ? 0 : -1);
	if (data_len < 2)
		return (-1);

	salt_len = ((data[0] >> 7) & 1) + (data[1] >> 4);
	iv_len = ((data[0] >> 6) & 1) + (data[1] & 0x0f);
	if (salt_len > sizeof(properties->salt) ||
	    iv_len > sizeof(properties->iv) ||
	    data_len != 2 + salt_len + iv_len)
		return (-1);

	properties->salt_len = salt_len;
	properties->iv_len = iv_len;
	memcpy(properties->salt, data + 2, salt_len);
	memcpy(properties->iv, data + 2 + salt_len, iv_len);
	return (0);
}

int
__archive_7zip_password_utf16le(const char *password, uint8_t **utf16,
    size_t *utf16_len)
{
	return (__archive_cryptor_utf8_to_utf16le(password, utf16,
	    utf16_len));
}

int
__archive_7zip_aes_derive_key(
    const struct archive_7zip_aes_properties *properties,
    const uint8_t *password, size_t password_len,
    uint8_t key[ARCHIVE_7ZIP_AES_KEY_SIZE])
{
	archive_sha256_ctx ctx;
	static const uint8_t empty_password = 0;
	const uint8_t *password_data;
	uint64_t rounds, counter;

	if (properties == NULL || key == NULL ||
	    (password == NULL && password_len != 0) ||
	    properties->salt_len > sizeof(properties->salt))
		return (-1);
	password_data = password_len == 0 ? &empty_password : password;
	if (properties->cycles_power == 0x3f) {
		size_t offset = 0, copy_len;

		memset(key, 0, ARCHIVE_7ZIP_AES_KEY_SIZE);
		copy_len = properties->salt_len;
		if (copy_len > ARCHIVE_7ZIP_AES_KEY_SIZE)
			copy_len = ARCHIVE_7ZIP_AES_KEY_SIZE;
		memcpy(key, properties->salt, copy_len);
		offset = copy_len;
		copy_len = password_len;
		if (copy_len > ARCHIVE_7ZIP_AES_KEY_SIZE - offset)
			copy_len = ARCHIVE_7ZIP_AES_KEY_SIZE - offset;
		if (copy_len != 0)
			memcpy(key + offset, password_data, copy_len);
		return (0);
	}
	if (properties->cycles_power > ARCHIVE_7ZIP_AES_MAX_CYCLES_POWER)
		return (-1);
	if (archive_sha256_init(&ctx) != ARCHIVE_OK)
		return (-2);
	rounds = UINT64_C(1) << properties->cycles_power;
	for (counter = 0; counter < rounds; counter++) {
		uint8_t counter_le[8];
		unsigned i;

		for (i = 0; i < sizeof(counter_le); i++)
			counter_le[i] = (uint8_t)(counter >> (i * 8));
		if (archive_sha256_update(&ctx, properties->salt,
		    properties->salt_len) != ARCHIVE_OK ||
		    archive_sha256_update(&ctx, password_data, password_len) !=
		    ARCHIVE_OK ||
		    archive_sha256_update(&ctx, counter_le,
		    sizeof(counter_le)) != ARCHIVE_OK) {
			archive_sha256_final(&ctx, key);
			__archive_cryptor_secure_zero(key,
			    ARCHIVE_7ZIP_AES_KEY_SIZE);
			return (-2);
		}
	}
	if (archive_sha256_final(&ctx, key) != ARCHIVE_OK) {
		__archive_cryptor_secure_zero(key, ARCHIVE_7ZIP_AES_KEY_SIZE);
		return (-2);
	}
	return (0);
}
