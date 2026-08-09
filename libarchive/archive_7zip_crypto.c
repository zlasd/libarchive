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

static int
utf8_codepoint(const uint8_t **input, const uint8_t *end,
    uint32_t *codepoint)
{
	const uint8_t *p = *input;
	uint32_t c;

	if (p[0] < 0x80) {
		*codepoint = p[0];
		*input = p + 1;
		return (0);
	}
	if (p[0] >= 0xc2 && p[0] <= 0xdf) {
		if ((size_t)(end - p) < 2)
			return (-1);
		if ((p[1] & 0xc0) != 0x80)
			return (-1);
		c = ((uint32_t)(p[0] & 0x1f) << 6) | (p[1] & 0x3f);
		*input = p + 2;
	} else if (p[0] >= 0xe0 && p[0] <= 0xef) {
		if ((size_t)(end - p) < 3)
			return (-1);
		if ((p[1] & 0xc0) != 0x80 || (p[2] & 0xc0) != 0x80 ||
		    (p[0] == 0xe0 && p[1] < 0xa0) ||
		    (p[0] == 0xed && p[1] >= 0xa0))
			return (-1);
		c = ((uint32_t)(p[0] & 0x0f) << 12) |
		    ((uint32_t)(p[1] & 0x3f) << 6) | (p[2] & 0x3f);
		*input = p + 3;
	} else if (p[0] >= 0xf0 && p[0] <= 0xf4) {
		if ((size_t)(end - p) < 4)
			return (-1);
		if ((p[1] & 0xc0) != 0x80 || (p[2] & 0xc0) != 0x80 ||
		    (p[3] & 0xc0) != 0x80 ||
		    (p[0] == 0xf0 && p[1] < 0x90) ||
		    (p[0] == 0xf4 && p[1] >= 0x90))
			return (-1);
		c = ((uint32_t)(p[0] & 0x07) << 18) |
		    ((uint32_t)(p[1] & 0x3f) << 12) |
		    ((uint32_t)(p[2] & 0x3f) << 6) | (p[3] & 0x3f);
		*input = p + 4;
	} else
		return (-1);

	*codepoint = c;
	return (0);
}

int
__archive_7zip_password_utf16le(const char *password, uint8_t **utf16,
    size_t *utf16_len)
{
	const uint8_t *p, *end;
	uint8_t *out, *q;
	size_t input_len;

	if (password == NULL || utf16 == NULL || utf16_len == NULL)
		return (-1);
	*utf16 = NULL;
	*utf16_len = 0;
	input_len = strlen(password);
	if (input_len > SIZE_MAX / 2)
		return (-1);
	out = malloc(input_len == 0 ? 1 : input_len * 2);
	if (out == NULL)
		return (-2);

	p = (const uint8_t *)password;
	end = p + input_len;
	q = out;
	while (p < end) {
		uint32_t c;

		if (utf8_codepoint(&p, end, &c) != 0) {
			free(out);
			return (-1);
		}
		if (c <= 0xffff) {
			*q++ = (uint8_t)c;
			*q++ = (uint8_t)(c >> 8);
		} else {
			uint32_t v = c - 0x10000;
			uint16_t high = (uint16_t)(0xd800 | (v >> 10));
			uint16_t low = (uint16_t)(0xdc00 | (v & 0x3ff));

			*q++ = (uint8_t)high;
			*q++ = (uint8_t)(high >> 8);
			*q++ = (uint8_t)low;
			*q++ = (uint8_t)(low >> 8);
		}
	}
	*utf16 = out;
	*utf16_len = (size_t)(q - out);
	return (0);
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
