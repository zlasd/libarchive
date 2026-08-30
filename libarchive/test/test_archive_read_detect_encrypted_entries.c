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
detect_encryption(const char *filename)
{
	struct archive *a;
	int result;

	extract_reference_file(filename);
	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_filter_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_all(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_read_open_filename(a, filename, 10240));
	result = archive_read_detect_encrypted_entries(a);
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
	return (result);
}

DEFINE_TEST(test_archive_read_detect_encrypted_entries)
{
	/* Unencrypted ZIP, 7-Zip, RAR4, and RAR5 archives. */
	assertEqualInt(0,
	    detect_encryption("test_read_format_zip.zip"));
	assertEqualInt(0,
	    detect_encryption("test_read_format_7zip_copy.7z"));
	assertEqualInt(0,
	    detect_encryption("test_read_format_rar.rar"));
	assertEqualInt(0,
	    detect_encryption("test_read_format_rar5_stored.rar"));

	/* Data encryption visible in ordinary entry headers. */
	assertEqualInt(1,
	    detect_encryption("test_read_format_zip_encryption_data.zip"));
	assertEqualInt(1,
	    detect_encryption("test_read_format_7zip_encryption.7z"));
	assertEqualInt(1,
	    detect_encryption("test_read_format_rar_encryption_data.rar"));

	/* Metadata encryption must be detected even when no header is readable. */
	assertEqualInt(1,
	    detect_encryption("test_read_format_7zip_encryption_header.7z"));
	assertEqualInt(1,
	    detect_encryption("test_read_format_rar4_encrypted_filenames.rar"));
	assertEqualInt(1,
	    detect_encryption("test_read_format_rar5_encrypted_filenames.rar"));
}
