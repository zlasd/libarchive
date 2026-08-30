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

#include "archive.h"

#include <emscripten/emscripten.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define MAOU_ARCHIVE_ERROR_CAPACITY 512

static char maou_archive_error[MAOU_ARCHIVE_ERROR_CAPACITY];

static void
clear_error(void)
{
	maou_archive_error[0] = '\0';
}

static void
capture_error(struct archive *a, const char *fallback)
{
	const char *message = a == NULL ? NULL : archive_error_string(a);

	if (message == NULL || message[0] == '\0')
		message = fallback;
	if (message == NULL)
		message = "Unknown archive error";
	snprintf(maou_archive_error, sizeof(maou_archive_error), "%s", message);
}

static struct archive *
new_reader(const char *passphrase)
{
	struct archive *a = archive_read_new();

	if (a == NULL) {
		capture_error(NULL, "Could not allocate an archive reader");
		return (NULL);
	}

	/* Upload packages are ZIP, 7z, or RAR. Register only those readers so
	 * unrelated format and external-program support is not pulled into WASM. */
	if (archive_read_support_filter_none(a) != ARCHIVE_OK ||
	    archive_read_support_format_zip(a) != ARCHIVE_OK ||
	    archive_read_support_format_7zip(a) != ARCHIVE_OK ||
	    archive_read_support_format_rar(a) != ARCHIVE_OK ||
	    archive_read_support_format_rar5(a) != ARCHIVE_OK) {
		capture_error(a, "Could not initialize archive readers");
		archive_read_free(a);
		return (NULL);
	}

	/* libarchive deliberately rejects an empty passphrase. Treat it like no
	 * candidate so the caller receives REQUIRED for an encrypted archive. */
	if (passphrase != NULL && passphrase[0] != '\0' &&
	    archive_read_add_passphrase(a, passphrase) != ARCHIVE_OK) {
		capture_error(a, "Could not register the archive passphrase");
		archive_read_free(a);
		return (NULL);
	}

	return (a);
}

static int
run_memory(const void *data, size_t size, const char *passphrase, int validate)
{
	struct archive *a;
	int result;

	clear_error();
	if (data == NULL || size == 0) {
		capture_error(NULL, "Archive data is empty");
		return (validate ? ARCHIVE_READ_PASSPHRASE_DONT_KNOW :
		    ARCHIVE_READ_FORMAT_ENCRYPTION_DONT_KNOW);
	}

	a = new_reader(passphrase);
	if (a == NULL)
		return (validate ? ARCHIVE_READ_PASSPHRASE_DONT_KNOW :
		    ARCHIVE_READ_FORMAT_ENCRYPTION_DONT_KNOW);

	if (archive_read_open_memory(a, data, size) != ARCHIVE_OK) {
		capture_error(a, "Could not open archive data");
		archive_read_free(a);
		return (validate ? ARCHIVE_READ_PASSPHRASE_DONT_KNOW :
		    ARCHIVE_READ_FORMAT_ENCRYPTION_DONT_KNOW);
	}

	result = validate ? archive_read_validate_passphrase(a) :
	    archive_read_detect_encrypted_entries(a);
	if (result < 0 || (validate &&
	    result == ARCHIVE_READ_PASSPHRASE_INVALID_OR_DAMAGED))
		capture_error(a, NULL);
	archive_read_free(a);
	return (result);
}

static int
run_path(const char *path, const char *passphrase, int validate)
{
	struct archive *a;
	int result;

	clear_error();
	if (path == NULL || path[0] == '\0') {
		capture_error(NULL, "Archive path is empty");
		return (validate ? ARCHIVE_READ_PASSPHRASE_DONT_KNOW :
		    ARCHIVE_READ_FORMAT_ENCRYPTION_DONT_KNOW);
	}

	a = new_reader(passphrase);
	if (a == NULL)
		return (validate ? ARCHIVE_READ_PASSPHRASE_DONT_KNOW :
		    ARCHIVE_READ_FORMAT_ENCRYPTION_DONT_KNOW);

	if (archive_read_open_filename(a, path, 64 * 1024) != ARCHIVE_OK) {
		capture_error(a, "Could not open archive path");
		archive_read_free(a);
		return (validate ? ARCHIVE_READ_PASSPHRASE_DONT_KNOW :
		    ARCHIVE_READ_FORMAT_ENCRYPTION_DONT_KNOW);
	}

	result = validate ? archive_read_validate_passphrase(a) :
	    archive_read_detect_encrypted_entries(a);
	if (result < 0 || (validate &&
	    result == ARCHIVE_READ_PASSPHRASE_INVALID_OR_DAMAGED))
		capture_error(a, NULL);
	archive_read_free(a);
	return (result);
}

EMSCRIPTEN_KEEPALIVE int
maou_archive_detect_encryption(const void *data, size_t size)
{
	return (run_memory(data, size, NULL, 0));
}

EMSCRIPTEN_KEEPALIVE int
maou_archive_validate_passphrase(const void *data, size_t size,
    const char *passphrase)
{
	return (run_memory(data, size, passphrase, 1));
}

EMSCRIPTEN_KEEPALIVE int
maou_archive_detect_encryption_path(const char *path)
{
	return (run_path(path, NULL, 0));
}

EMSCRIPTEN_KEEPALIVE int
maou_archive_validate_passphrase_path(const char *path,
    const char *passphrase)
{
	return (run_path(path, passphrase, 1));
}

EMSCRIPTEN_KEEPALIVE const char *
maou_archive_last_error(void)
{
	return (maou_archive_error);
}

EMSCRIPTEN_KEEPALIVE const char *
maou_archive_version(void)
{
	return (archive_version_string());
}
