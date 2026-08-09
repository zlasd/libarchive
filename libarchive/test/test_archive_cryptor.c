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

#include "test.h"

#define __LIBARCHIVE_BUILD 1
#include "archive_7zip_crypto_private.h"
#include "archive_cryptor_private.h"
#include "archive_digest_private.h"
#include "archive_hmac_private.h"
#include "archive_rar_crypto_private.h"

DEFINE_TEST(test_archive_7zip_aes_properties)
{
	static const unsigned char full[] = {
		0xcc, 0x7f,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
		0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f
	};
	static const unsigned char simple[] = { 0x13 };
	struct archive_7zip_aes_properties properties;

	assertEqualInt(0, __archive_7zip_aes_parse_properties(simple,
	    sizeof(simple), &properties));
	assertEqualInt(19, properties.cycles_power);
	assertEqualInt(0, properties.salt_len);
	assertEqualInt(0, properties.iv_len);
	assertMemoryFilledWith(properties.iv, sizeof(properties.iv), 0);

	assertEqualInt(0, __archive_7zip_aes_parse_properties(full,
	    sizeof(full), &properties));
	assertEqualInt(12, properties.cycles_power);
	assertEqualInt(8, properties.salt_len);
	assertEqualInt(16, properties.iv_len);
	assertEqualMem(full + 2, properties.salt, properties.salt_len);
	assertEqualMem(full + 10, properties.iv, properties.iv_len);

	assertEqualInt(-1, __archive_7zip_aes_parse_properties(NULL, 0,
	    &properties));
	assertEqualInt(-1, __archive_7zip_aes_parse_properties(simple, 0,
	    &properties));
	assertEqualInt(-1, __archive_7zip_aes_parse_properties(full,
	    sizeof(full) - 1, &properties));
	assertEqualInt(-1, __archive_7zip_aes_parse_properties(full,
	    sizeof(full), NULL));
}

DEFINE_TEST(test_archive_7zip_password_utf16le)
{
	static const unsigned char expected_ascii[] = {
		'p', 0, 'a', 0, 's', 0, 's', 0
	};
	static const unsigned char expected_unicode[] = {
		0xc6, 0x5b, 0x01, 0x78, 0x3d, 0xd8, 0x12, 0xdd
	};
	static const char *invalid[] = {
		"\xc0\x80", "\xed\xa0\x80", "\xf4\x90\x80\x80", "\xe2\x82"
	};
	unsigned char *actual = NULL;
	size_t actual_len = 0, i;

	assertEqualInt(0, __archive_7zip_password_utf16le("pass", &actual,
	    &actual_len));
	assertEqualInt(sizeof(expected_ascii), actual_len);
	assertEqualMem(expected_ascii, actual, actual_len);
	free(actual);

	actual = NULL;
	assertEqualInt(0, __archive_7zip_password_utf16le(
	    "\xe5\xaf\x86\xe7\xa0\x81\xf0\x9f\x94\x92", &actual,
	    &actual_len));
	assertEqualInt(sizeof(expected_unicode), actual_len);
	assertEqualMem(expected_unicode, actual, actual_len);
	free(actual);

	for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		actual = NULL;
		assertEqualInt(-1, __archive_7zip_password_utf16le(invalid[i],
		    &actual, &actual_len));
		assert(actual == NULL);
	}
}

DEFINE_TEST(test_archive_7zip_aes_kdf)
{
	static const unsigned char salt[] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
	};
	static const unsigned char expected[] = {
		0xd8, 0xd1, 0x2e, 0x9d, 0x0a, 0xfd, 0xbe, 0x28,
		0x04, 0xd4, 0x29, 0x05, 0x7c, 0x0d, 0xdb, 0x8d,
		0x4f, 0xf8, 0x05, 0xed, 0x8d, 0xd1, 0x7f, 0x79,
		0x6d, 0xb7, 0xc4, 0x50, 0x09, 0x1b, 0x53, 0x77
	};
	static const unsigned char password[] = {
		'p', 0, 'a', 0, 's', 0, 's', 0, 'w', 0, 'o', 0, 'r', 0, 'd', 0
	};
	struct archive_7zip_aes_properties properties;
	unsigned char actual[ARCHIVE_7ZIP_AES_KEY_SIZE];

	memset(&properties, 0, sizeof(properties));
	properties.cycles_power = 12;
	properties.salt_len = sizeof(salt);
	memcpy(properties.salt, salt, sizeof(salt));
	assertEqualInt(0, __archive_7zip_aes_derive_key(&properties, password,
	    sizeof(password), actual));
	assertEqualMem(expected, actual, sizeof(expected));

	properties.cycles_power = 0x3f;
	assertEqualInt(0, __archive_7zip_aes_derive_key(&properties, password,
	    sizeof(password), actual));
	assertEqualMem(salt, actual, sizeof(salt));
	assertEqualMem(password, actual + sizeof(salt), sizeof(password));
	assertMemoryFilledWith(actual + sizeof(salt) + sizeof(password),
	    sizeof(actual) - sizeof(salt) - sizeof(password), 0);

	properties.cycles_power = ARCHIVE_7ZIP_AES_MAX_CYCLES_POWER + 1;
	assertEqualInt(-1, __archive_7zip_aes_derive_key(&properties, password,
	    sizeof(password), actual));
	__archive_cryptor_secure_zero(actual, sizeof(actual));
}

DEFINE_TEST(test_archive_rar5_aes_kdf)
{
	static const unsigned char salt[ARCHIVE_RAR5_SALT_SIZE] = {
		0xc7, 0x44, 0x5e, 0xe1, 0x80, 0xf8, 0xb5, 0x9f,
		0xd6, 0x2b, 0x43, 0x37, 0x08, 0xbc, 0x57, 0xcd
	};
	static const unsigned char expected[ARCHIVE_RAR5_KEY_SIZE] = {
		0xd7, 0x5c, 0x7c, 0xb7, 0xe2, 0x2d, 0x81, 0x13,
		0x8d, 0x1a, 0x15, 0x98, 0x8c, 0x78, 0x5d, 0x51,
		0x41, 0xb4, 0xfa, 0x5c, 0x2a, 0x69, 0x1a, 0x49,
		0x50, 0x5a, 0xbb, 0x7d, 0x60, 0xae, 0xe6, 0x90
	};
	static const unsigned char check[ARCHIVE_RAR5_CHECK_SIZE] = {
		0xea, 0x35, 0x67, 0x1d, 0x70, 0xf1, 0x2d, 0x4b,
		0x6b, 0x9c, 0x1a, 0x9c
	};
	unsigned char actual[ARCHIVE_RAR5_KEY_SIZE];
	unsigned char invalid_check[ARCHIVE_RAR5_CHECK_SIZE];
	int r;

	r = __archive_rar5_derive_key("password", salt, 15, actual);
	if (r == CRYPTOR_STUB_FUNCTION) {
		skipping("This platform does not support RAR5 key derivation");
		return;
	}
	assertEqualInt(0, r);
	assertEqualMem(expected, actual, sizeof(expected));
	assertEqualInt(1, __archive_rar5_check_value_is_valid(check));
	memcpy(invalid_check, check, sizeof(check));
	invalid_check[ARCHIVE_RAR5_CHECK_SIZE - 1] ^= 1;
	assertEqualInt(0, __archive_rar5_check_value_is_valid(invalid_check));
	assertEqualInt(-1, __archive_rar5_derive_key("password", salt,
	    ARCHIVE_RAR5_MAX_KDF_COUNT + 1, actual));
	__archive_cryptor_secure_zero(actual, sizeof(actual));
}

DEFINE_TEST(test_archive_cryptor_secure_zero)
{
	unsigned char secret[32];
	size_t i;

	memset(secret, 0xa5, sizeof(secret));
	__archive_cryptor_secure_zero(secret, sizeof(secret));
	for (i = 0; i < sizeof(secret); i++)
		assertEqualInt(0, secret[i]);
}

DEFINE_TEST(test_archive_cryptor_constant_time_equal)
{
	static const unsigned char value[] = { 0, 1, 2, 3, 4, 5 };
	unsigned char different[sizeof(value)];

	memcpy(different, value, sizeof(value));
	assertEqualInt(1, __archive_cryptor_constant_time_equal(
	    value, different, sizeof(value)));

	different[0] ^= 1;
	assertEqualInt(0, __archive_cryptor_constant_time_equal(
	    value, different, sizeof(value)));
	different[0] ^= 1;
	different[sizeof(different) - 1] ^= 1;
	assertEqualInt(0, __archive_cryptor_constant_time_equal(
	    value, different, sizeof(value)));

	assertEqualInt(1, __archive_cryptor_constant_time_equal(
	    value, different, 0));
}

DEFINE_TEST(test_archive_sha1_clone)
{
	static const unsigned char expected_abc[20] = {
		0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
		0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
		0x9c, 0xd0, 0xd8, 0x9d
	};
	static const unsigned char expected_abd[20] = {
		0xcb, 0x4c, 0xc2, 0x8d, 0xf0, 0xfd, 0xbe, 0x0e,
		0xcf, 0x9d, 0x96, 0x62, 0xe2, 0x94, 0xb1, 0x18,
		0x09, 0x2a, 0x57, 0x35
	};
	archive_sha1_ctx original, copy;
	unsigned char digest[20];

	assertEqualInt(ARCHIVE_OK, archive_sha1_init(&original));
	assertEqualInt(ARCHIVE_OK, archive_sha1_update(&original, "ab", 2));
	if (archive_sha1_clone(&copy, &original) != ARCHIVE_OK) {
		assertEqualInt(ARCHIVE_OK, archive_sha1_final(&original, digest));
		skipping("This platform cannot clone SHA-1 contexts");
		return;
	}
	assertEqualInt(ARCHIVE_OK, archive_sha1_update(&original, "c", 1));
	assertEqualInt(ARCHIVE_OK, archive_sha1_final(&original, digest));
	assertEqualMem(expected_abc, digest, sizeof(digest));
	assertEqualInt(ARCHIVE_OK, archive_sha1_update(&copy, "d", 1));
	assertEqualInt(ARCHIVE_OK, archive_sha1_final(&copy, digest));
	assertEqualMem(expected_abd, digest, sizeof(digest));
	__archive_cryptor_secure_zero(digest, sizeof(digest));
}

static void
test_aes_cbc(const unsigned char *key, size_t key_len,
    const unsigned char *ciphertext, const unsigned char *plaintext)
{
	static const unsigned char iv[16] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	};
	static const size_t chunks[] = { 1, 15, 17, 31 };
	archive_crypto_ctx ctx;
	unsigned char actual[80];
	size_t actual_len = 0, input_offset = 0, i;
	int result;

	memset(&ctx, 0, sizeof(ctx));
	result = archive_decrypto_aes_cbc_init(&ctx, key, key_len, iv);
	if (result == CRYPTOR_STUB_FUNCTION) {
		skipping("This platform does not support AES-CBC");
		return;
	}
	assertEqualInt(0, result);

	for (i = 0; i < sizeof(chunks) / sizeof(chunks[0]); i++) {
		size_t written = sizeof(actual) - actual_len;
		assertEqualInt(0, archive_decrypto_aes_cbc_update(&ctx,
		    ciphertext + input_offset, chunks[i], actual + actual_len,
		    &written));
		input_offset += chunks[i];
		actual_len += written;
	}
	assertEqualInt(64, input_offset);
	assertEqualInt(64, actual_len);
	assertEqualMem(plaintext, actual, actual_len);
	assertEqualInt(0, archive_decrypto_aes_cbc_release(&ctx));
	assertMemoryFilledWith(&ctx, sizeof(ctx), 0);
}

DEFINE_TEST(test_archive_cryptor_aes128_cbc)
{
	static const unsigned char key[16] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	};
	static const unsigned char ciphertext[64] = {
		0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
		0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
		0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
		0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
		0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b,
		0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
		0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09,
		0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7
	};
	static const unsigned char plaintext[64] = {
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
		0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
		0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
		0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
		0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
		0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
		0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
		0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
	};

	test_aes_cbc(key, sizeof(key), ciphertext, plaintext);
}

DEFINE_TEST(test_archive_cryptor_aes256_cbc)
{
	static const unsigned char key[32] = {
		0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
		0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
		0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
	};
	static const unsigned char ciphertext[64] = {
		0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba,
		0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
		0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d,
		0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
		0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf,
		0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
		0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc,
		0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b
	};
	static const unsigned char plaintext[64] = {
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
		0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
		0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
		0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
		0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
		0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
		0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
		0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
	};

	test_aes_cbc(key, sizeof(key), ciphertext, plaintext);
}

DEFINE_TEST(test_archive_cryptor_pbkdf2_sha256)
{
	static const unsigned char expected[32] = {
		0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41,
		0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d,
		0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11,
		0xa4, 0x96, 0x38, 0x73, 0xaa, 0x98, 0x13, 0x4a
	};
	unsigned char actual[sizeof(expected)];
	int result;

	result = archive_pbkdf2_sha256("password", 8,
	    (const unsigned char *)"salt", 4, 4096, actual, sizeof(actual));
	if (result == CRYPTOR_STUB_FUNCTION) {
		skipping("This platform does not support PBKDF2-HMAC-SHA256");
		return;
	}
	assertEqualInt(0, result);
	assertEqualMem(expected, actual, sizeof(expected));
	__archive_cryptor_secure_zero(actual, sizeof(actual));
}

DEFINE_TEST(test_archive_cryptor_hmac_sha256)
{
	static const unsigned char key[20] = {
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b
	};
	static const unsigned char expected[32] = {
		0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
		0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
		0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
		0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
	};
	static const unsigned char data[] = "Hi There";
	archive_hmac_sha256_ctx ctx;
	unsigned char actual[sizeof(expected)];
	size_t actual_len = sizeof(actual);

	if (archive_hmac_sha256_init(&ctx, key, sizeof(key)) != 0) {
		skipping("This platform does not support HMAC-SHA256");
		return;
	}
	archive_hmac_sha256_update(&ctx, data, 2);
	archive_hmac_sha256_update(&ctx, data + 2, sizeof(data) - 3);
	archive_hmac_sha256_final(&ctx, actual, &actual_len);
	assertEqualInt(sizeof(expected), actual_len);
	assertEqualMem(expected, actual, sizeof(expected));
	archive_hmac_sha256_cleanup(&ctx);
	__archive_cryptor_secure_zero(actual, sizeof(actual));
}
