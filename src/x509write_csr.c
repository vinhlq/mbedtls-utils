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

#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls-utils/x509_csr.h"

int x509write_csr_set
	(
		mbedtls_x509write_csr *ctx,
		const x509write_csr_mandatory *mandatory,
		const x509write_csr_optional *optional
	)
{
	int ret;

	mbedtls_x509write_csr_set_md_alg( ctx, mandatory->md );

	if(optional && optional->key_usage)
	{
		mbedtls_printf( "  . Adding the Key Usage extension ..." );
		if( (ret = mbedtls_x509write_csr_set_key_usage( ctx, *optional->key_usage) ) )
		{
			char buf[256];

			mbedtls_strerror( ret, buf, sizeof(buf) );
			mbedtls_printf( " failed\n  !  mbedtls_x509write_csr_set_subject_name "
							"returned -0x%04x - %s\n\n", -ret, buf );
			return ret;
		}
		mbedtls_printf( " ok\n" );
	}

	if(optional && optional->ns_cert_type)
	{
		mbedtls_printf( "  . Adding the NS Cert Type extension ..." );
		if( (ret = mbedtls_x509write_csr_set_ns_cert_type( ctx, *optional->ns_cert_type) ) )
		{
			char buf[256];

			mbedtls_strerror( ret, buf, sizeof(buf) );
			mbedtls_printf( " failed\n  !  mbedtls_x509write_csr_set_subject_name "
							"returned -0x%04x - %s\n\n", -ret, buf );
			return ret;
		}
		mbedtls_printf( " ok\n" );
	}

	mbedtls_printf( "  . Setting the object name ..." );
//	if( (ret = mbedtls_x509write_csr_set_subject_name( &ctx, "CN=Cert,O=mbed TLS,C=UK") ) )
	if( (ret = mbedtls_x509write_csr_set_subject_name( ctx, mandatory->subject_name) ) )
	{
		char buf[256];

		mbedtls_strerror( ret, buf, sizeof(buf) );
		mbedtls_printf( " failed\n  !  mbedtls_x509write_csr_set_subject_name "
						"returned -0x%04x - %s\n\n", -ret, buf );
		return ret;
	}
	mbedtls_printf( " ok\n" );

	mbedtls_x509write_csr_set_key( ctx, mandatory->key );

	return ret;
}

int x509write_csr_write_csr
	(
		mbedtls_x509write_csr *ctx,
		mbedtls_x509_csr *csr
	)
{
#define X509_CSR_GEN_DER
#define X509_CSR_GEN_DER_SIZE	(1024)
#define X509_CSR_GEN_DER_USE_ALLOC
	int ret;
#ifdef X509_CSR_GEN_DER_USE_ALLOC
	char *der_buf;
#else
	char der_buf[X509_CSR_GEN_DER_SIZE];
#endif

#ifdef X509_CSR_GEN_DER_USE_ALLOC
	der_buf = mbedtls_calloc(X509_CSR_GEN_DER_SIZE, 1);
	if(!der_buf)
	{
		mbedtls_printf( " failed\n  !  cannot alloc %d(bytes)", X509_CSR_GEN_DER_SIZE );
		return -1;
	}
#endif

#if defined(X509_CSR_GEN_DER)
	if( ( ret = x509write_csr_write_der_buffer( ctx, (unsigned char *)der_buf, X509_CSR_GEN_DER_SIZE ) ) < 0 )
	{
		goto exit;
	}
#elif defined(X509_CSR_GEN_PEM)
	if( ( ret = x509write_csr_write_pem_buffer( ctx, (unsigned char *)der_buf, X509_CSR_GEN_DER_SIZE ) ) < 0 )
	{
		goto exit;
	}
#else
	if( ( ret = x509write_csr_write_pem( ctx, DFL_OUTPUT_FILENAME) ) != 0 )
	{
		mbedtls_printf( " failed\n  !  write_certifcate_request %d", ret );
		goto exit;
	}
#endif

#if defined(MBEDTLS_X509_CSR_PARSE_C)
	mbedtls_printf( "  . Loading the certificate request ..." );
	fflush( stdout );

#if defined(X509_CSR_GEN_DER)
	if( ( ret = mbedtls_x509_csr_parse_der( csr,
											(unsigned char *)der_buf + X509_CSR_GEN_DER_SIZE - ret,
											ret) ) )
	{
		mbedtls_strerror( ret, der_buf, X509_CSR_GEN_DER_SIZE );
		mbedtls_printf( " failed\n  !  mbedtls_x509_csr_parse_der "
						"returned -0x%04x - %s\n\n", -ret, der_buf );
		goto exit;
	}
#elif defined(X509_CSR_GEN_PEM)
	if( ( ret = mbedtls_x509_csr_parse( csr,
										(unsigned char *)der_buf,
										strlen(buf)+1) ) )
	{
		mbedtls_strerror( ret, der_buf, X509_CSR_GEN_DER_SIZE );
		mbedtls_printf( " failed\n  !  mbedtls_x509_csr_parse "
						"returned -0x%04x - %s\n\n", -ret, der_buf );
		goto exit;
	}
#elif defined(MBEDTLS_FS_IO)
	if( ( ret = mbedtls_x509_csr_parse_file( csr, DFL_OUTPUT_FILENAME ) ) != 0 )
	{
		mbedtls_strerror( ret, der_buf, X509_CSR_GEN_DER_SIZE );
		mbedtls_printf( " failed\n  !  mbedtls_x509_csr_parse_file "
						"returned -0x%04x - %s\n\n", -ret, der_buf );
		goto exit;
	}
#endif
	mbedtls_printf( " ok\n" );
#endif // #if defined(MBEDTLS_X509_CSR_PARSE_C)

exit:
#ifdef X509_CSR_GEN_DER_USE_ALLOC
	mbedtls_free(der_buf);
#endif
	return ret;
}

int x509write_csr_write_der_buffer
	(
		mbedtls_x509write_csr *ctx,
		unsigned char *buffer, int length
	)
{
	int ret;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *pers = "csr random";

	mbedtls_ctr_drbg_init( &ctr_drbg );
	mbedtls_entropy_init( &entropy );

	mbedtls_printf( "  . Seeding the random number generator..." );
	if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
							   (const unsigned char *) pers,
							   strlen( pers ) ) ) != 0 )
	{
		mbedtls_printf( " failed\n  !  mbedtls_ctr_drbg_seed returned %d", ret );
		goto exit;
	}
	mbedtls_printf( " ok\n" );

	mbedtls_printf( "  . Writing the certificate request..." );
	memset( buffer, 0, length );
	if( ( ret = mbedtls_x509write_csr_der( ctx, buffer, length, mbedtls_ctr_drbg_random, &ctr_drbg ) ) < 0 )
	{
		mbedtls_strerror( ret, (char *)buffer, length );
		mbedtls_printf( " failed\n  !  mbedtls_x509write_csr_der -0x%04x - %s\n\n",
						-ret, buffer );
		goto exit;
	}

	mbedtls_printf( " ok\n" );

exit:
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );
	return( ret );
}

int x509write_csr_write_pem_buffer
	(
		mbedtls_x509write_csr *ctx,
		unsigned char *buffer, int length
	)
{
	int ret;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *pers = "csr random";

	mbedtls_ctr_drbg_init( &ctr_drbg );
	mbedtls_entropy_init( &entropy );

	mbedtls_printf( "  . Seeding the random number generator..." );
	if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
							   (const unsigned char *) pers,
							   strlen( pers ) ) ) != 0 )
	{
		mbedtls_printf( " failed\n  !  mbedtls_ctr_drbg_seed returned %d", ret );
		goto exit;
	}
	mbedtls_printf( " ok\n" );

	mbedtls_printf( "  . Writing the certificate request..." );
	memset( buffer, 0, length );
	if( ( ret = mbedtls_x509write_csr_pem( ctx, buffer, length, mbedtls_ctr_drbg_random, &ctr_drbg ) ) < 0 )
	{
		mbedtls_strerror( ret, (char *)buffer, length );
		mbedtls_printf( " failed\n  !  mbedtls_x509write_csr_pem -0x%04x - %s\n\n",
						-ret, buffer );
		goto exit;
	}

	mbedtls_printf( " ok\n" );

exit:
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );
	return( ret );
}

#ifdef MBEDTLS_FS_IO
int x509write_csr_write_pem
	(
		mbedtls_x509write_csr *ctx,
		const char *output_file
	)
{
    int ret;
    FILE *f;
    unsigned char output_buf[4096];
    size_t len = 0;

    if( ( ret = x509write_csr_write_pem_buffer( ctx, output_buf, 4096 ) ) < 0 )
        return( ret );

    len = strlen( (char *) output_buf );

    if( ( f = fopen( output_file, "w" ) ) == NULL )
        return( -1 );

    if( fwrite( output_buf, 1, len, f ) != len )
    {
        fclose( f );
        return( -1 );
    }

    fclose( f );

    return( 0 );
}
#endif

