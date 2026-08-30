/*-
 * Copyright (c) 2026 Maou Console contributors
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

static int
validate_passphrases(const char *filename, const char *const *passphrases,
    size_t passphrase_count)
{
	struct archive *a;
	int result;
	size_t i;

	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_filter_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_all(a));
	for (i = 0; i < passphrase_count; i++)
		assertEqualIntA(a, ARCHIVE_OK,
		    archive_read_add_passphrase(a, passphrases[i]));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_read_open_filename(a, filename, 10240));
	result = archive_read_validate_passphrase(a);
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
	return (result);
}

static int
validate_passphrase(const char *filename, const char *passphrase)
{
	return (validate_passphrases(filename, &passphrase,
	    passphrase == NULL ? 0 : 1));
}

static void
assert_passphrase_status(int expected, const char *filename,
    const char *passphrase)
{
	int actual = validate_passphrase(filename, passphrase);

	failure("Passphrase status for %s with %s password", filename,
	    passphrase == NULL ? "no" : passphrase);
	assertEqualInt(expected, actual);
}

DEFINE_TEST(test_archive_read_validate_passphrase)
{
	const char *unencrypted[] = {
		"test_read_format_zip_mac_metadata.zip",
		"test_read_format_7zip_copy.7z",
		"test_read_format_rar.rar",
		"test_read_format_rar5_stored.rar"
	};
	struct encrypted_fixture {
		const char *filename;
		const char *passphrase;
	} encrypted[] = {
		{"test_read_format_zip_traditional_encryption_data.zip",
		    "12345678"},
		{"test_read_format_zip_winzip_aes256_stored.zip", "password"},
		{"test_read_format_7zip_encryption.7z", "12345678"},
		{"test_read_format_7zip_encryption_header.7z", "12345678"},
		{"test_read_format_rar_encryption_data.rar", "12345678"},
		{"test_read_format_rar4_encrypted_filenames.rar", "password"},
		{"test_read_format_rar5_encrypted_filenames.rar", "password"},
		{"test_read_format_rar5_encrypted_quickopen.rar", "密碼🔒"},
		{"test_read_format_rar5_encrypted_blake2.rar", "password"}
	};
	const char *mixed_passwords[] = {"password", "password2"};
	const char *damaged = "test_read_format_rar5_encrypted_blake2.rar";
	FILE *f;
	int byte;
	size_t i;

	for (i = 0; i < sizeof(unencrypted) / sizeof(unencrypted[0]); i++) {
		extract_reference_file(unencrypted[i]);
		assert_passphrase_status(ARCHIVE_READ_PASSPHRASE_NOT_NEEDED,
		    unencrypted[i], NULL);
		assert_passphrase_status(ARCHIVE_READ_PASSPHRASE_NOT_NEEDED,
		    unencrypted[i], "unused");
	}

	for (i = 0; i < sizeof(encrypted) / sizeof(encrypted[0]); i++) {
		extract_reference_file(encrypted[i].filename);
		assert_passphrase_status(ARCHIVE_READ_PASSPHRASE_REQUIRED,
		    encrypted[i].filename, NULL);
		assert_passphrase_status(ARCHIVE_READ_PASSPHRASE_VALID,
		    encrypted[i].filename, encrypted[i].passphrase);
		assert_passphrase_status(
		    ARCHIVE_READ_PASSPHRASE_INVALID_OR_DAMAGED,
		    encrypted[i].filename, "definitely-wrong");
	}

	/* A non-solid RAR may use different passwords for different entries.
	 * Validation must read the entire archive and try all configured
	 * candidates instead of accepting the first successfully decrypted file. */
	extract_reference_file("test_read_format_rar5_encrypted.rar");
	assertEqualInt(ARCHIVE_READ_PASSPHRASE_VALID,
	    validate_passphrases("test_read_format_rar5_encrypted.rar",
	    mixed_passwords, sizeof(mixed_passwords) / sizeof(mixed_passwords[0])));
	assertEqualInt(ARCHIVE_READ_PASSPHRASE_INVALID_OR_DAMAGED,
	    validate_passphrase("test_read_format_rar5_encrypted.rar",
	    "password"));

	/* Do not claim that a valid password can distinguish damaged ciphertext.
	 * This fixture's offset 200 is inside its encrypted stored payload. */
	assert((f = fopen(damaged, "r+b")) != NULL);
	assertEqualInt(0, fseek(f, 200, SEEK_SET));
	assert((byte = fgetc(f)) != EOF);
	assertEqualInt(0, fseek(f, 200, SEEK_SET));
	assert(fputc(byte ^ 1, f) != EOF);
	assertEqualInt(0, fclose(f));
	assert_passphrase_status(ARCHIVE_READ_PASSPHRASE_INVALID_OR_DAMAGED,
	    damaged, "password");
}
