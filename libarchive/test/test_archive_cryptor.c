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
#include "archive_cryptor_private.h"

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
