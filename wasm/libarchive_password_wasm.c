/*-
 * Copyright (c) 2026 libarchive-password-wasm contributors
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
#include "archive_entry.h"

#include <emscripten/emscripten.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LIBARCHIVE_PASSWORD_ERROR_CAPACITY 512
#define LIBARCHIVE_PASSWORD_LIST_OK 0
#define LIBARCHIVE_PASSWORD_LIST_ERROR -1

static char libarchive_password_error[LIBARCHIVE_PASSWORD_ERROR_CAPACITY];
static char **libarchive_password_entries;
static size_t libarchive_password_entry_count;
static size_t libarchive_password_entry_capacity;

static void capture_error(struct archive *, const char *);

static void
clear_error(void)
{
	libarchive_password_error[0] = '\0';
}

static void
clear_entries(void)
{
	size_t index;

	for (index = 0; index < libarchive_password_entry_count; index++)
		free(libarchive_password_entries[index]);
	free(libarchive_password_entries);
	libarchive_password_entries = NULL;
	libarchive_password_entry_count = 0;
	libarchive_password_entry_capacity = 0;
}

static int
append_entry(const char *path)
{
	char **entries;
	char *copy;
	size_t capacity, length;

	if (path == NULL)
		return (ARCHIVE_OK);

	if (libarchive_password_entry_count ==
	    libarchive_password_entry_capacity) {
		capacity = libarchive_password_entry_capacity == 0 ? 64 :
		    libarchive_password_entry_capacity * 2;
		entries = (char **)realloc(libarchive_password_entries,
		    capacity * sizeof(*entries));
		if (entries == NULL) {
			capture_error(NULL, "Could not allocate the archive file list");
			return (ARCHIVE_FATAL);
		}
		libarchive_password_entries = entries;
		libarchive_password_entry_capacity = capacity;
	}

	length = strlen(path) + 1;
	copy = (char *)malloc(length);
	if (copy == NULL) {
		capture_error(NULL, "Could not allocate an archive path");
		return (ARCHIVE_FATAL);
	}
	memcpy(copy, path, length);
	libarchive_password_entries[libarchive_password_entry_count++] = copy;
	return (ARCHIVE_OK);
}

static void
capture_error(struct archive *a, const char *fallback)
{
	const char *message = a == NULL ? NULL : archive_error_string(a);

	if (message == NULL || message[0] == '\0')
		message = fallback;
	if (message == NULL)
		message = "Unknown archive error";
	snprintf(libarchive_password_error, sizeof(libarchive_password_error),
	    "%s", message);
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

static int
list_path(const char *path, const char *passphrase)
{
	struct archive_entry *entry;
	struct archive *a;
	const char *entry_path;
	int result;

	clear_error();
	clear_entries();
	if (path == NULL || path[0] == '\0') {
		capture_error(NULL, "Archive path is empty");
		return (LIBARCHIVE_PASSWORD_LIST_ERROR);
	}

	a = new_reader(passphrase);
	if (a == NULL)
		return (LIBARCHIVE_PASSWORD_LIST_ERROR);

	if (archive_read_open_filename(a, path, 64 * 1024) != ARCHIVE_OK) {
		capture_error(a, "Could not open archive path");
		archive_read_free(a);
		return (LIBARCHIVE_PASSWORD_LIST_ERROR);
	}

	for (;;) {
		entry = NULL;
		result = archive_read_next_header(a, &entry);
		if (result == ARCHIVE_EOF)
			break;
		if (result < ARCHIVE_WARN || entry == NULL) {
			capture_error(a, "Could not read the archive file list");
			archive_read_free(a);
			clear_entries();
			return (LIBARCHIVE_PASSWORD_LIST_ERROR);
		}

		entry_path = archive_entry_pathname_utf8(entry);
		if (entry_path == NULL)
			entry_path = archive_entry_pathname(entry);
		if (append_entry(entry_path) != ARCHIVE_OK) {
			archive_read_free(a);
			clear_entries();
			return (LIBARCHIVE_PASSWORD_LIST_ERROR);
		}
	}

	archive_read_free(a);
	return (LIBARCHIVE_PASSWORD_LIST_OK);
}

EMSCRIPTEN_KEEPALIVE int
libarchive_password_detect_encryption(const void *data, size_t size)
{
	return (run_memory(data, size, NULL, 0));
}

EMSCRIPTEN_KEEPALIVE int
libarchive_password_validate_passphrase(const void *data, size_t size,
    const char *passphrase)
{
	return (run_memory(data, size, passphrase, 1));
}

EMSCRIPTEN_KEEPALIVE int
libarchive_password_detect_encryption_path(const char *path)
{
	return (run_path(path, NULL, 0));
}

EMSCRIPTEN_KEEPALIVE int
libarchive_password_validate_passphrase_path(const char *path,
    const char *passphrase)
{
	return (run_path(path, passphrase, 1));
}

EMSCRIPTEN_KEEPALIVE int
libarchive_password_list_path(const char *path, const char *passphrase)
{
	return (list_path(path, passphrase));
}

EMSCRIPTEN_KEEPALIVE size_t
libarchive_password_list_count(void)
{
	return (libarchive_password_entry_count);
}

EMSCRIPTEN_KEEPALIVE const char *
libarchive_password_list_entry(size_t index)
{
	if (index >= libarchive_password_entry_count)
		return (NULL);
	return (libarchive_password_entries[index]);
}

EMSCRIPTEN_KEEPALIVE const char *
libarchive_password_last_error(void)
{
	return (libarchive_password_error);
}

EMSCRIPTEN_KEEPALIVE const char *
libarchive_password_version(void)
{
	return (archive_version_string());
}
