/*-
* Copyright (c) 2014 Michihiro NAKAJIMA
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
* IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "archive_platform.h"

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "archive.h"
#include "archive_cryptor_private.h"

/*
 * On systems that do not support any recognized crypto libraries,
 * this file will normally define no usable symbols.
 *
 * But some compilers and linkers choke on empty object files, so
 * define a public symbol that will always exist.  This could
 * be removed someday if this file gains another always-present
 * symbol definition.
 */
int __libarchive_cryptor_build_hack(void) {
	return 0;
}

void
__archive_cryptor_secure_zero(void *buffer, size_t length)
{
	volatile unsigned char *p = (volatile unsigned char *)buffer;

	while (length-- > 0)
		*p++ = 0;
}

int
__archive_cryptor_constant_time_equal(const void *left, const void *right,
    size_t length)
{
	const unsigned char *l = (const unsigned char *)left;
	const unsigned char *r = (const unsigned char *)right;
	unsigned char difference = 0;

	while (length-- > 0)
		difference |= *l++ ^ *r++;
	return difference == 0;
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
		if ((size_t)(end - p) < 2 || (p[1] & 0xc0) != 0x80)
			return (-1);
		c = ((uint32_t)(p[0] & 0x1f) << 6) | (p[1] & 0x3f);
		*input = p + 2;
	} else if (p[0] >= 0xe0 && p[0] <= 0xef) {
		if ((size_t)(end - p) < 3 || (p[1] & 0xc0) != 0x80 ||
		    (p[2] & 0xc0) != 0x80 ||
		    (p[0] == 0xe0 && p[1] < 0xa0) ||
		    (p[0] == 0xed && p[1] >= 0xa0))
			return (-1);
		c = ((uint32_t)(p[0] & 0x0f) << 12) |
		    ((uint32_t)(p[1] & 0x3f) << 6) | (p[2] & 0x3f);
		*input = p + 3;
	} else if (p[0] >= 0xf0 && p[0] <= 0xf4) {
		if ((size_t)(end - p) < 4 || (p[1] & 0xc0) != 0x80 ||
		    (p[2] & 0xc0) != 0x80 || (p[3] & 0xc0) != 0x80 ||
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
__archive_cryptor_utf8_to_utf16le(const char *input, uint8_t **utf16,
    size_t *utf16_len)
{
	const uint8_t *p, *end;
	uint8_t *out, *q;
	size_t input_len;

	if (input == NULL || utf16 == NULL || utf16_len == NULL)
		return (-1);
	*utf16 = NULL;
	*utf16_len = 0;
	input_len = strlen(input);
	if (input_len > SIZE_MAX / 2)
		return (-1);
	out = malloc(input_len == 0 ? 1 : input_len * 2);
	if (out == NULL)
		return (-2);

	p = (const uint8_t *)input;
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

#ifdef ARCHIVE_CRYPTOR_USE_Apple_CommonCrypto

static int
pbkdf2_sha1(const char *pw, size_t pw_len, const uint8_t *salt,
    size_t salt_len, unsigned rounds, uint8_t *derived_key,
    size_t derived_key_len)
{
	CCKeyDerivationPBKDF(kCCPBKDF2, (const char *)pw,
	    pw_len, salt, salt_len, kCCPRFHmacAlgSHA1, rounds,
	    derived_key, derived_key_len);
	return 0;
}

#elif defined(_WIN32) && !defined(__CYGWIN__) && defined(HAVE_BCRYPT_H)
#ifdef _MSC_VER
#pragma comment(lib, "Bcrypt.lib")
#endif

static int
pbkdf2_sha1(const char *pw, size_t pw_len, const uint8_t *salt,
	size_t salt_len, unsigned rounds, uint8_t *derived_key,
	size_t derived_key_len)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlg;

	status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM,
		MS_PRIMITIVE_PROVIDER, BCRYPT_ALG_HANDLE_HMAC_FLAG);
	if (!BCRYPT_SUCCESS(status))
		return -1;

	status = BCryptDeriveKeyPBKDF2(hAlg,
		(PUCHAR)(uintptr_t)pw, (ULONG)pw_len,
		(PUCHAR)(uintptr_t)salt, (ULONG)salt_len, rounds,
		(PUCHAR)derived_key, (ULONG)derived_key_len, 0);

	BCryptCloseAlgorithmProvider(hAlg, 0);

	return (BCRYPT_SUCCESS(status)) ? 0: -1;
}

#elif defined(HAVE_LIBMBEDCRYPTO) && defined(HAVE_MBEDTLS_PKCS5_H)

static int
pbkdf2_sha1(const char *pw, size_t pw_len, const uint8_t *salt,
    size_t salt_len, unsigned rounds, uint8_t *derived_key,
    size_t derived_key_len)
{
	mbedtls_md_context_t ctx;
	const mbedtls_md_info_t *info;
	int ret;

	mbedtls_md_init(&ctx);
	info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
	if (info == NULL) {
		mbedtls_md_free(&ctx);
		return (-1);
	}
	ret = mbedtls_md_setup(&ctx, info, 1);
	if (ret != 0) {
		mbedtls_md_free(&ctx);
		return (-1);
	}
	ret = mbedtls_pkcs5_pbkdf2_hmac(&ctx, (const unsigned char *)pw,
	    pw_len, salt, salt_len, rounds, derived_key_len, derived_key);

	mbedtls_md_free(&ctx);
	return (ret);
}

#elif defined(HAVE_LIBNETTLE) && defined(HAVE_NETTLE_PBKDF2_H)

static int
pbkdf2_sha1(const char *pw, size_t pw_len, const uint8_t *salt,
    size_t salt_len, unsigned rounds, uint8_t *derived_key,
    size_t derived_key_len) {
	pbkdf2_hmac_sha1((unsigned)pw_len, (const uint8_t *)pw, rounds,
	    salt_len, salt, derived_key_len, derived_key);
	return 0;
}

#elif defined(HAVE_LIBCRYPTO) && defined(HAVE_PKCS5_PBKDF2_HMAC_SHA1)

static int
pbkdf2_sha1(const char *pw, size_t pw_len, const uint8_t *salt,
    size_t salt_len, unsigned rounds, uint8_t *derived_key,
    size_t derived_key_len) {

	PKCS5_PBKDF2_HMAC_SHA1(pw, pw_len, salt, salt_len, rounds,
	    derived_key_len, derived_key);
	return 0;
}

#else

/* Stub */
static int
pbkdf2_sha1(const char *pw, size_t pw_len, const uint8_t *salt,
    size_t salt_len, unsigned rounds, uint8_t *derived_key,
    size_t derived_key_len) {
	(void)pw; /* UNUSED */
	(void)pw_len; /* UNUSED */
	(void)salt; /* UNUSED */
	(void)salt_len; /* UNUSED */
	(void)rounds; /* UNUSED */
	(void)derived_key; /* UNUSED */
	(void)derived_key_len; /* UNUSED */
	return CRYPTOR_STUB_FUNCTION; /* UNSUPPORTED */
}

#endif

#ifdef ARCHIVE_CRYPTOR_USE_Apple_CommonCrypto

static int
pbkdf2_sha256(const char *pw, size_t pw_len, const uint8_t *salt,
    size_t salt_len, unsigned rounds, uint8_t *derived_key,
    size_t derived_key_len)
{
	CCCryptorStatus status;

	status = CCKeyDerivationPBKDF(kCCPBKDF2, pw, pw_len, salt, salt_len,
	    kCCPRFHmacAlgSHA256, rounds, derived_key, derived_key_len);
	return status == kCCSuccess ? 0 : -1;
}

#elif defined(ARCHIVE_CRYPTOR_USE_OPENSSL) && \
    defined(HAVE_PKCS5_PBKDF2_HMAC)

static int
pbkdf2_sha256(const char *pw, size_t pw_len, const uint8_t *salt,
    size_t salt_len, unsigned rounds, uint8_t *derived_key,
    size_t derived_key_len)
{
	if (pw_len > INT_MAX || salt_len > INT_MAX || rounds > INT_MAX ||
	    derived_key_len > INT_MAX)
		return -1;
	return PKCS5_PBKDF2_HMAC(pw, (int)pw_len, salt, (int)salt_len,
	    (int)rounds, EVP_sha256(), (int)derived_key_len, derived_key) == 1 ?
	    0 : -1;
}

#else

static int
pbkdf2_sha256(const char *pw, size_t pw_len, const uint8_t *salt,
    size_t salt_len, unsigned rounds, uint8_t *derived_key,
    size_t derived_key_len)
{
	(void)pw;
	(void)pw_len;
	(void)salt;
	(void)salt_len;
	(void)rounds;
	(void)derived_key;
	(void)derived_key_len;
	return CRYPTOR_STUB_FUNCTION;
}

#endif

#ifdef ARCHIVE_CRYPTOR_USE_Apple_CommonCrypto
# if MAC_OS_X_VERSION_MAX_ALLOWED < 1090
#  define kCCAlgorithmAES kCCAlgorithmAES128
# endif

static int
aes_ctr_init(archive_crypto_ctx *ctx, const uint8_t *key, size_t key_len)
{
	CCCryptorStatus r;

	ctx->key_len = key_len;
	memcpy(ctx->key, key, key_len);
	memset(ctx->nonce, 0, sizeof(ctx->nonce));
	ctx->encr_pos = AES_BLOCK_SIZE;
	r = CCCryptorCreateWithMode(kCCEncrypt, kCCModeECB, kCCAlgorithmAES,
	    ccNoPadding, NULL, key, key_len, NULL, 0, 0, 0, &ctx->ctx);
	return (r == kCCSuccess)? 0: -1;
}

static int
aes_ctr_encrypt_counter(archive_crypto_ctx *ctx)
{
	CCCryptorRef ref = ctx->ctx;
	CCCryptorStatus r;

	r = CCCryptorReset(ref, NULL);
	if (r != kCCSuccess && r != kCCUnimplemented)
		return -1;
	r = CCCryptorUpdate(ref, ctx->nonce, AES_BLOCK_SIZE, ctx->encr_buf,
	    AES_BLOCK_SIZE, NULL);
	return (r == kCCSuccess)? 0: -1;
}

static int
aes_ctr_release(archive_crypto_ctx *ctx)
{
	memset(ctx->key, 0, ctx->key_len);
	memset(ctx->nonce, 0, sizeof(ctx->nonce));
	return 0;
}

#elif defined(_WIN32) && !defined(__CYGWIN__) && defined(HAVE_BCRYPT_H)

static int
aes_ctr_init(archive_crypto_ctx *ctx, const uint8_t *key, size_t key_len)
{
	BCRYPT_ALG_HANDLE hAlg;
	BCRYPT_KEY_HANDLE hKey;
	DWORD keyObj_len, aes_key_len;
	PBYTE keyObj;
	ULONG result;
	NTSTATUS status;
	BCRYPT_KEY_LENGTHS_STRUCT key_lengths;

	ctx->hAlg = NULL;
	ctx->hKey = NULL;
	ctx->keyObj = NULL;
	switch (key_len) {
	case 16: aes_key_len = 128; break;
	case 24: aes_key_len = 192; break;
	case 32: aes_key_len = 256; break;
	default: return -1;
	}
	status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM,
		MS_PRIMITIVE_PROVIDER, 0);
	if (!BCRYPT_SUCCESS(status))
		return -1;
	status = BCryptGetProperty(hAlg, BCRYPT_KEY_LENGTHS, (PUCHAR)&key_lengths,
		sizeof(key_lengths), &result, 0);
	if (!BCRYPT_SUCCESS(status)) {
		BCryptCloseAlgorithmProvider(hAlg, 0);
		return -1;
	}
	if (key_lengths.dwMinLength > aes_key_len
		|| key_lengths.dwMaxLength < aes_key_len) {
		BCryptCloseAlgorithmProvider(hAlg, 0);
		return -1;
	}
	status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObj_len,
		sizeof(keyObj_len), &result, 0);
	if (!BCRYPT_SUCCESS(status)) {
		BCryptCloseAlgorithmProvider(hAlg, 0);
		return -1;
	}
	keyObj = (PBYTE)HeapAlloc(GetProcessHeap(), 0, keyObj_len);
	if (keyObj == NULL) {
		BCryptCloseAlgorithmProvider(hAlg, 0);
		return -1;
	}
	status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
		(PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
	if (!BCRYPT_SUCCESS(status)) {
		BCryptCloseAlgorithmProvider(hAlg, 0);
		HeapFree(GetProcessHeap(), 0, keyObj);
		return -1;
	}
	status = BCryptGenerateSymmetricKey(hAlg, &hKey,
		keyObj, keyObj_len,
		(PUCHAR)(uintptr_t)key, (ULONG)key_len, 0);
	if (!BCRYPT_SUCCESS(status)) {
		BCryptCloseAlgorithmProvider(hAlg, 0);
		HeapFree(GetProcessHeap(), 0, keyObj);
		return -1;
	}

	ctx->hAlg = hAlg;
	ctx->hKey = hKey;
	ctx->keyObj = keyObj;
	ctx->keyObj_len = keyObj_len;
	ctx->encr_pos = AES_BLOCK_SIZE;

	return 0;
}

static int
aes_ctr_encrypt_counter(archive_crypto_ctx *ctx)
{
	NTSTATUS status;
	ULONG result;

	status = BCryptEncrypt(ctx->hKey, (PUCHAR)ctx->nonce, AES_BLOCK_SIZE,
		NULL, NULL, 0, (PUCHAR)ctx->encr_buf, AES_BLOCK_SIZE,
		&result, 0);
	return BCRYPT_SUCCESS(status) ? 0 : -1;
}

static int
aes_ctr_release(archive_crypto_ctx *ctx)
{

	if (ctx->hAlg != NULL) {
		BCryptCloseAlgorithmProvider(ctx->hAlg, 0);
		ctx->hAlg = NULL;
		BCryptDestroyKey(ctx->hKey);
		ctx->hKey = NULL;
		HeapFree(GetProcessHeap(), 0, ctx->keyObj);
		ctx->keyObj = NULL;
	}
	memset(ctx, 0, sizeof(*ctx));
	return 0;
}

#elif defined(HAVE_LIBMBEDCRYPTO) && defined(HAVE_MBEDTLS_AES_H)

static int
aes_ctr_init(archive_crypto_ctx *ctx, const uint8_t *key, size_t key_len)
{
	mbedtls_aes_init(&ctx->ctx);
	ctx->key_len = key_len;
	memcpy(ctx->key, key, key_len);
	memset(ctx->nonce, 0, sizeof(ctx->nonce));
	ctx->encr_pos = AES_BLOCK_SIZE;
	return 0;
}

static int
aes_ctr_encrypt_counter(archive_crypto_ctx *ctx)
{
	if (mbedtls_aes_setkey_enc(&ctx->ctx, ctx->key,
	    ctx->key_len * 8) != 0)
		return (-1);
	if (mbedtls_aes_crypt_ecb(&ctx->ctx, MBEDTLS_AES_ENCRYPT, ctx->nonce,
	    ctx->encr_buf) != 0)
		return (-1);
	return 0;
}

static int
aes_ctr_release(archive_crypto_ctx *ctx)
{
	mbedtls_aes_free(&ctx->ctx);
	memset(ctx, 0, sizeof(*ctx));
	return 0;
}

#elif defined(HAVE_LIBNETTLE) && defined(HAVE_NETTLE_AES_H)

static int
aes_ctr_init(archive_crypto_ctx *ctx, const uint8_t *key, size_t key_len)
{
	ctx->key_len = key_len;
	memcpy(ctx->key, key, key_len);
	memset(ctx->nonce, 0, sizeof(ctx->nonce));
	ctx->encr_pos = AES_BLOCK_SIZE;
	memset(&ctx->ctx, 0, sizeof(ctx->ctx));
	return 0;
}

static int
aes_ctr_encrypt_counter(archive_crypto_ctx *ctx)
{
#if NETTLE_VERSION_MAJOR < 3
	aes_set_encrypt_key(&ctx->ctx, ctx->key_len, ctx->key);
	aes_encrypt(&ctx->ctx, AES_BLOCK_SIZE, ctx->encr_buf, ctx->nonce);
#else
	switch(ctx->key_len) {
	case AES128_KEY_SIZE:
		aes128_set_encrypt_key(&ctx->ctx.c128, ctx->key);
		aes128_encrypt(&ctx->ctx.c128, AES_BLOCK_SIZE, ctx->encr_buf,
		    ctx->nonce);
		break;
	case AES192_KEY_SIZE:
		aes192_set_encrypt_key(&ctx->ctx.c192, ctx->key);
		aes192_encrypt(&ctx->ctx.c192, AES_BLOCK_SIZE, ctx->encr_buf,
		    ctx->nonce);
		break;
	case AES256_KEY_SIZE:
		aes256_set_encrypt_key(&ctx->ctx.c256, ctx->key);
		aes256_encrypt(&ctx->ctx.c256, AES_BLOCK_SIZE, ctx->encr_buf,
		    ctx->nonce);
		break;
	default:
		return -1;
		break;
	}
#endif
	return 0;
}

static int
aes_ctr_release(archive_crypto_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	return 0;
}

#elif defined(HAVE_LIBCRYPTO)

static int
aes_ctr_init(archive_crypto_ctx *ctx, const uint8_t *key, size_t key_len)
{
	if ((ctx->ctx = EVP_CIPHER_CTX_new()) == NULL)
		return -1;

	switch (key_len) {
	case 16: ctx->type = EVP_aes_128_ecb(); break;
	case 24: ctx->type = EVP_aes_192_ecb(); break;
	case 32: ctx->type = EVP_aes_256_ecb(); break;
	default: ctx->type = NULL; return -1;
	}

	ctx->key_len = key_len;
	memcpy(ctx->key, key, key_len);
	memset(ctx->nonce, 0, sizeof(ctx->nonce));
	ctx->encr_pos = AES_BLOCK_SIZE;
	return 0;
}

static int
aes_ctr_encrypt_counter(archive_crypto_ctx *ctx)
{
	int outl = 0;
	int r;

	r = EVP_EncryptInit_ex(ctx->ctx, ctx->type, NULL, ctx->key, NULL);
	if (r == 0)
		return -1;
	r = EVP_EncryptUpdate(ctx->ctx, ctx->encr_buf, &outl, ctx->nonce,
	    AES_BLOCK_SIZE);
	if (r == 0 || outl != AES_BLOCK_SIZE)
		return -1;
	return 0;
}

static int
aes_ctr_release(archive_crypto_ctx *ctx)
{
	EVP_CIPHER_CTX_free(ctx->ctx);
	OPENSSL_cleanse(ctx->key, ctx->key_len);
	OPENSSL_cleanse(ctx->nonce, sizeof(ctx->nonce));
	return 0;
}

#else

#define ARCHIVE_CRYPTOR_STUB
/* Stub */
static int
aes_ctr_init(archive_crypto_ctx *ctx, const uint8_t *key, size_t key_len)
{
	(void)ctx; /* UNUSED */
	(void)key; /* UNUSED */
	(void)key_len; /* UNUSED */
	return CRYPTOR_STUB_FUNCTION;
}

static int
aes_ctr_encrypt_counter(archive_crypto_ctx *ctx)
{
	(void)ctx; /* UNUSED */
	return CRYPTOR_STUB_FUNCTION;
}

static int
aes_ctr_release(archive_crypto_ctx *ctx)
{
	(void)ctx; /* UNUSED */
	return 0;
}

#endif

#ifdef ARCHIVE_CRYPTOR_STUB
static int
aes_ctr_update(archive_crypto_ctx *ctx, const uint8_t * const in,
    size_t in_len, uint8_t * const out, size_t *out_len)
{
	(void)ctx; /* UNUSED */
	(void)in; /* UNUSED */
	(void)in_len; /* UNUSED */
	(void)out; /* UNUSED */
	(void)out_len; /* UNUSED */
	aes_ctr_encrypt_counter(ctx); /* UNUSED */ /* Fix unused function warning */
	return CRYPTOR_STUB_FUNCTION;
}

#else
static void
aes_ctr_increase_counter(archive_crypto_ctx *ctx)
{
	uint8_t *const nonce = ctx->nonce;
	int j;

	for (j = 0; j < 8; j++) {
		if (++nonce[j])
			break;
	}
}

static int
aes_ctr_update(archive_crypto_ctx *ctx, const uint8_t * const in,
    size_t in_len, uint8_t * const out, size_t *out_len)
{
	uint8_t *const ebuf = ctx->encr_buf;
	size_t pos = ctx->encr_pos;
	size_t max = (in_len < *out_len)? in_len: *out_len;
	size_t i;

	for (i = 0; i < max; ) {
		if (pos == AES_BLOCK_SIZE) {
			aes_ctr_increase_counter(ctx);
			if (aes_ctr_encrypt_counter(ctx) != 0)
				return -1;
			while (max -i >= AES_BLOCK_SIZE) {
				for (pos = 0; pos < AES_BLOCK_SIZE; pos++)
					out[i+pos] = in[i+pos] ^ ebuf[pos];
				i += AES_BLOCK_SIZE;
				aes_ctr_increase_counter(ctx);
				if (aes_ctr_encrypt_counter(ctx) != 0)
					return -1;
			}
			pos = 0;
			if (i >= max)
				break;
		}
		out[i] = in[i] ^ ebuf[pos++];
		i++;
	}
	ctx->encr_pos = pos;
	*out_len = i;

	return 0;
}
#endif /* ARCHIVE_CRYPTOR_STUB */

#ifdef ARCHIVE_CRYPTOR_USE_Apple_CommonCrypto

static int
aes_cbc_decrypt_init(archive_crypto_ctx *ctx, const uint8_t *key,
    size_t key_len, const uint8_t *iv)
{
	CCCryptorStatus status;

	if (key_len != kCCKeySizeAES128 && key_len != kCCKeySizeAES256)
		return -1;
	memset(ctx, 0, sizeof(*ctx));
	status = CCCryptorCreate(kCCDecrypt, kCCAlgorithmAES, 0, key, key_len,
	    iv, &ctx->ctx);
	if (status != kCCSuccess) {
		__archive_cryptor_secure_zero(ctx, sizeof(*ctx));
		return -1;
	}
	memcpy(ctx->key, key, key_len);
	ctx->key_len = key_len;
	memcpy(ctx->nonce, iv, AES_BLOCK_SIZE);
	return 0;
}

static int
aes_cbc_decrypt_update(archive_crypto_ctx *ctx, const uint8_t *in,
    size_t in_len, uint8_t *out, size_t *out_len)
{
	CCCryptorStatus status;
	size_t required, written = 0;

	required = CCCryptorGetOutputLength(ctx->ctx, in_len, false);
	if (required > *out_len)
		return -1;
	status = CCCryptorUpdate(ctx->ctx, in, in_len, out, *out_len, &written);
	if (status != kCCSuccess)
		return -1;
	*out_len = written;
	return 0;
}

static int
aes_cbc_decrypt_release(archive_crypto_ctx *ctx)
{
	if (ctx->ctx != NULL)
		CCCryptorRelease(ctx->ctx);
	__archive_cryptor_secure_zero(ctx, sizeof(*ctx));
	return 0;
}

#elif defined(ARCHIVE_CRYPTOR_USE_OPENSSL)

static int
aes_cbc_decrypt_init(archive_crypto_ctx *ctx, const uint8_t *key,
    size_t key_len, const uint8_t *iv)
{
	const EVP_CIPHER *type;

	if (key_len == 16)
		type = EVP_aes_128_cbc();
	else if (key_len == 32)
		type = EVP_aes_256_cbc();
	else
		return -1;

	memset(ctx, 0, sizeof(*ctx));
	ctx->ctx = EVP_CIPHER_CTX_new();
	if (ctx->ctx == NULL)
		return -1;
	if (EVP_DecryptInit_ex(ctx->ctx, type, NULL, key, iv) != 1 ||
	    EVP_CIPHER_CTX_set_padding(ctx->ctx, 0) != 1) {
		EVP_CIPHER_CTX_free(ctx->ctx);
		__archive_cryptor_secure_zero(ctx, sizeof(*ctx));
		return -1;
	}
	ctx->type = type;
	memcpy(ctx->key, key, key_len);
	ctx->key_len = (unsigned)key_len;
	memcpy(ctx->nonce, iv, AES_BLOCK_SIZE);
	return 0;
}

static int
aes_cbc_decrypt_update(archive_crypto_ctx *ctx, const uint8_t *in,
    size_t in_len, uint8_t *out, size_t *out_len)
{
	int written;

	if (in_len > INT_MAX || in_len > SIZE_MAX - AES_BLOCK_SIZE ||
	    *out_len < in_len + AES_BLOCK_SIZE)
		return -1;
	if (EVP_DecryptUpdate(ctx->ctx, out, &written, in, (int)in_len) != 1)
		return -1;
	*out_len = (size_t)written;
	return 0;
}

static int
aes_cbc_decrypt_release(archive_crypto_ctx *ctx)
{
	EVP_CIPHER_CTX_free(ctx->ctx);
	__archive_cryptor_secure_zero(ctx, sizeof(*ctx));
	return 0;
}

#else

static int
aes_cbc_decrypt_init(archive_crypto_ctx *ctx, const uint8_t *key,
    size_t key_len, const uint8_t *iv)
{
	(void)ctx;
	(void)key;
	(void)key_len;
	(void)iv;
	return CRYPTOR_STUB_FUNCTION;
}

static int
aes_cbc_decrypt_update(archive_crypto_ctx *ctx, const uint8_t *in,
    size_t in_len, uint8_t *out, size_t *out_len)
{
	(void)ctx;
	(void)in;
	(void)in_len;
	(void)out;
	(void)out_len;
	return CRYPTOR_STUB_FUNCTION;
}

static int
aes_cbc_decrypt_release(archive_crypto_ctx *ctx)
{
	(void)ctx;
	return CRYPTOR_STUB_FUNCTION;
}

#endif


const struct archive_cryptor __archive_cryptor =
{
  &pbkdf2_sha1,
  &pbkdf2_sha256,
  &aes_ctr_init,
  &aes_ctr_update,
  &aes_ctr_release,
  &aes_cbc_decrypt_init,
  &aes_cbc_decrypt_update,
  &aes_cbc_decrypt_release,
  &aes_ctr_init,
  &aes_ctr_update,
  &aes_ctr_release,
};
