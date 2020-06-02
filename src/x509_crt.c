/*
 *  Certificate request generation
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#ifndef mbedtls_printf
#define mbedtls_printf(fmt,args...)      printf(fmt, ## args);	fflush(stdout);
#endif
#ifndef mbedtls_exit
#define mbedtls_exit            exit
#endif
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if !defined(MBEDTLS_X509_CSR_WRITE_C) ||  \
    !defined(MBEDTLS_PK_PARSE_C) || !defined(MBEDTLS_SHA256_C) || \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C) || \
    !defined(MBEDTLS_PEM_WRITE_C)
#error  "MBEDTLS_X509_CSR_WRITE_C and/or "	\
		"MBEDTLS_PK_PARSE_C and/or MBEDTLS_SHA256_C and/or "	\
		"MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C "	\
		"not defined.\n"
#endif

#ifndef MBEDTLS_UTILS_DEBUG_ENABLED
#undef mbedtls_printf
#define mbedtls_printf(...)
#endif

#include "mbedtls/base64.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha1.h"

#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls-utils/x509_crt.h"

static int binary2hex
	(
		unsigned char *buffer,
		int length,
		unsigned char *hex_buffer,
		int hex_buffer_length
	)
{
	int i;

	for (i = 0; length > 0; i++, length--)
	{
		uint8_t x = buffer[length-1] & 0x0F;

		if(hex_buffer_length < 3)
			break;
		if (x > 9) x += ('a'-'9'-1);
		hex_buffer[(length-1) * 2 + 1] = x + '0';
		hex_buffer_length--;

		x = buffer[length-1] >> 4;
		if (x > 9) x += ('a'-'9'-1);
		hex_buffer[(length-1) * 2] = x + '0';
		hex_buffer_length--;
	}
	hex_buffer[i*2] = '\0';
	return length;
}

static int convert_pem_to_der
	(
		const unsigned char *input, size_t ilen,
        unsigned char *output, size_t *olen
	)
{
    int ret;
    const unsigned char *s1, *s2, *end = input + ilen;
    size_t len = 0;

    s1 = (unsigned char *) strstr( (const char *) input, "-----BEGIN" );
    if( s1 == NULL )
        return( -1 );

    s2 = (unsigned char *) strstr( (const char *) input, "-----END" );
    if( s2 == NULL )
        return( -1 );

    s1 += 10;
    while( s1 < end && *s1 != '-' )
        s1++;
    while( s1 < end && *s1 == '-' )
        s1++;
    if( *s1 == '\r' ) s1++;
    if( *s1 == '\n' ) s1++;

    if( s2 <= s1 || s2 > end )
        return( -1 );

    ret = mbedtls_base64_decode( NULL, 0, &len, (const unsigned char *) s1, s2 - s1 );
    if( ret == MBEDTLS_ERR_BASE64_INVALID_CHARACTER )
        return( ret );

    if( len > *olen )
        return( -1 );

    if( ( ret = mbedtls_base64_decode( output, len, &len, (const unsigned char *) s1,
                               s2 - s1 ) ) != 0 )
    {
        return( ret );
    }

    *olen = len;

    return( 0 );
}

#define DER_BUFFER_SIZE	(1024)
int x509_crt_fingerprint_sha256
	(
		const unsigned char *pem, size_t size,
		unsigned char out[32]
	)
{
	int ret;
	unsigned char *der_buf;
	size_t der_length;

	der_buf = malloc(DER_BUFFER_SIZE);
	if(!der_buf)
		return -1;
	der_length = DER_BUFFER_SIZE;
	mbedtls_printf( "  . Convert pem to der ...");
	if( ( ret = convert_pem_to_der(pem, size, der_buf, &der_length) ) )
	{
		char buf[256];

		mbedtls_strerror( ret, (char *)buf, sizeof(buf) );
		mbedtls_printf( " failed\n  !  convert_pem_to_der "
						"returned -0x%04x - %s\n\n", -ret, buf );
		goto exit;
	}
	mbedtls_printf( " ok\n" );

	/* 0 here means use the full SHA-256, not the SHA-224 variant */
	mbedtls_sha256(der_buf, der_length, out, 0);

exit:
	free(der_buf);
	return ret;
}

int x509_crt_fingerprint_sha1
	(
		const unsigned char *pem, size_t size,
		unsigned char out[20]
	)
{
	int ret;
	unsigned char *der_buf;
	size_t der_length;

	der_buf = malloc(DER_BUFFER_SIZE);
	if(!der_buf)
		return -1;
	der_length = DER_BUFFER_SIZE;
	mbedtls_printf( "  . Convert pem to der ...");
	if( ( ret = convert_pem_to_der(pem, size, der_buf, &der_length) ) )
	{
		char buf[256];

		mbedtls_strerror( ret, (char *)buf, sizeof(buf) );
		mbedtls_printf( " failed\n  !  convert_pem_to_der "
						"returned -0x%04x - %s\n\n", -ret, buf );
		goto exit;
	}
	mbedtls_printf( " ok\n" );

	/* 0 here means use the full SHA-256, not the SHA-224 variant */
	mbedtls_sha1(der_buf, der_length, out);

exit:
	free(der_buf);
	return ret;
}

int x509_crt_fingerprint_sha256_hex
	(
		const unsigned char *pem, size_t size,
		unsigned char *buffer, size_t length
	)
{
	unsigned char sha256[32];
	int ret;

	if( ( ret = x509_crt_fingerprint_sha256(pem, size, sha256) ) )
	{
		return ret;
	}

	if( ( ret = binary2hex(sha256, sizeof(sha256), buffer, length) ) )
	{
		return -1;
	}

	return 0;
}

int x509_crt_fingerprint_sha1_hex
	(
		const unsigned char *pem, size_t size,
		unsigned char *buffer, size_t length
	)
{
	unsigned char sha1[20];
	int ret;

	if( ( ret = x509_crt_fingerprint_sha1(pem, size, sha1) ) )
	{
		return ret;
	}

	if( ( ret = binary2hex(sha1, sizeof(sha1), buffer, length) ) )
	{
		return -1;
	}

	return 0;
}

#ifdef MBEDTLS_FS_IO

#endif

