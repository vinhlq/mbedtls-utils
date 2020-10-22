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

#include "mbedtls/pem.h"
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

int x509write_crt_set_issuer
	(
		mbedtls_x509write_cert *ctx,
		mbedtls_pk_context *issuer_key,
		const char *issuer_name
	)
{
	int ret;

	mbedtls_printf( "  . Setting the issuer key ..." );
	mbedtls_x509write_crt_set_issuer_key( ctx, issuer_key );
    if( ( ret = mbedtls_x509write_crt_set_issuer_name( ctx, issuer_name ) ) != 0 )
    {
    	char buf[256];

        mbedtls_strerror( ret, buf, sizeof(buf) );
        mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_issuer_name "
                        "returned -0x%04x - %s\n\n", -ret, buf );
        return ret;
    }
    mbedtls_printf( " ok\n" );
    return ret;
}

int x509write_crt_set_subject
	(
		mbedtls_x509write_cert *ctx,
		mbedtls_pk_context *subject_key,
		const char *subject_name
	)
{
	int ret;

	mbedtls_printf( "  . Setting the subject key ..." );
	mbedtls_x509write_crt_set_subject_key( ctx, subject_key );
	if( ( ret = mbedtls_x509write_crt_set_subject_name( ctx, subject_name ) ) != 0 )
	{
		char buf[256];

		mbedtls_strerror( ret, buf, sizeof(buf) );
		mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_subject_name "
						"returned -0x%04x - %s\n\n", -ret, buf );
		return ret;
	}
	mbedtls_printf( " ok\n" );
	return 0;
}

int x509write_crt_set_subject_from_csr
	(
		mbedtls_x509write_cert *ctx,
		mbedtls_x509_csr *csr
	)
{
	int ret;
	char buf[256];

	mbedtls_printf( "  . Setting the subject key from csr..." );
	ret = mbedtls_x509_dn_gets( buf, sizeof(buf), &csr->subject );
	if( ret < 0 )
	{
		mbedtls_strerror( ret, buf, sizeof(buf) );
		mbedtls_printf( " failed\n  !  mbedtls_x509_dn_gets "
						"returned -0x%04x - %s\n\n", -ret, buf );
		return ret;
	}

	mbedtls_x509write_crt_set_subject_key( ctx, &csr->pk );
	if( ( ret = mbedtls_x509write_crt_set_subject_name( ctx, buf ) ) != 0 )
	{
		mbedtls_strerror( ret, buf, sizeof(buf) );
		mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_subject_name "
						"returned -0x%04x - %s\n\n", -ret, buf );
		return ret;
	}
	mbedtls_printf( " ok\n" );
	return 0;
}

int x509write_crt_set_serial_string
	(
		mbedtls_x509write_cert *ctx,
		int radix,
		const char *serial_string
	)
{
	char buf[256];
	int ret;
	mbedtls_mpi serial;

	mbedtls_mpi_init( &serial );
	// Parse serial to MPI
	//
	mbedtls_printf( "  . Reading serial number..." );

	if( ( ret = mbedtls_mpi_read_string( &serial, radix, serial_string ) ) != 0 )
	{
		mbedtls_strerror( ret, buf, sizeof(buf) );
		mbedtls_printf( " failed\n  !  mbedtls_mpi_read_string "
						"returned -0x%04x - %s\n\n", -ret, buf );
		goto exit;
	}

	if( ( ret = mbedtls_x509write_crt_set_serial( ctx, &serial ) ) )
	{
		mbedtls_strerror( ret, buf, sizeof(buf) );
		mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_serial "
						"returned -0x%04x - %s\n\n", -ret, buf );
		goto exit;
	}

	mbedtls_printf( " ok\n" );

exit:
	mbedtls_mpi_free( &serial );
	return ret;
}

int x509write_crt_set_serial_binary
	(
		mbedtls_x509write_cert *ctx,
		const unsigned char *serial_buf, size_t serial_buf_len
	)
{
	char buf[256];
	int ret;
	mbedtls_mpi serial;

	mbedtls_mpi_init( &serial );
	// Parse serial to MPI
	//
	mbedtls_printf( "  . Reading serial number..." );

	if( ( ret = mbedtls_mpi_read_binary( &serial, serial_buf, serial_buf_len ) ) != 0 )
	{
		mbedtls_strerror( ret, buf, sizeof(buf) );
		mbedtls_printf( " failed\n  !  mbedtls_mpi_read_string "
						"returned -0x%04x - %s\n\n", -ret, buf );
		goto exit;
	}

	if( ( ret = mbedtls_x509write_crt_set_serial( ctx, &serial ) ) )
	{
		mbedtls_strerror( ret, buf, sizeof(buf) );
		mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_serial "
						"returned -0x%04x - %s\n\n", -ret, buf );
		goto exit;
	}

	mbedtls_printf( " ok\n" );

exit:
	mbedtls_mpi_free( &serial );
	return ret;
}

int x509write_crt_setup
	(
		mbedtls_x509write_cert *ctx,
		x509write_crt_subject *subject,
		mbedtls_x509_crt *issuer_crt, mbedtls_pk_context *issuer_key,
		const x509write_crt_mandatory *mandatory,
		const x509write_crt_optional *optional
	)
{
	int ret;

	char issuer_name[256];

	/*
	 * 2. mandatory parameters
	 */

	mbedtls_printf( "  . Getting the issuer name ..." );
	ret = mbedtls_x509_dn_gets( issuer_name, sizeof(issuer_name), &issuer_crt->subject );
	if( ret < 0 )
	{
		char buf[256];

		mbedtls_strerror( ret, buf, sizeof(buf) );
		mbedtls_printf( " failed\n  !  mbedtls_x509_dn_gets "
						"returned -0x%04x - %s\n\n", -ret, buf );
		return ret;
	}
	mbedtls_printf( " ok\n" );

	// Check if key and issuer certificate match
	//
	mbedtls_printf( "  . Check if key and issuer certificate match..." );
	if( (ret = mbedtls_pk_check_pair( &issuer_crt->pk, issuer_key ) ) != 0 )
	{
		char buf[256];

		mbedtls_strerror( ret, buf, sizeof(buf) );
		mbedtls_printf( " failed\n  !  mbedtls_pk_check_pair "
						"returned -0x%04x - %s\n\n", -ret, buf );
	}
	mbedtls_printf( " ok\n" );

	// set subject key
	//
	if(subject)
	{
		if( ( ret = x509write_crt_set_subject(ctx, subject->pk, subject->name) ) )
		{
			return ret;
		}
	}
	else
	{
		// self signing
		if( ( ret = x509write_crt_set_subject(ctx, &issuer_crt->pk, issuer_name) ) )
		{
			return ret;
		}
	}

	// set issuer key
	//
	if( ( ret = x509write_crt_set_issuer(ctx, issuer_key, issuer_name) ) )
	{
		return ret;
	}

	// set serial number
	//
	switch(mandatory->serial_type)
	{
		case x509write_crt_serial_decimal:
			if( ( ret = x509write_crt_set_serial_string(ctx, 10, mandatory->serial_string) ) )
			{
				return ret;
			}
			break;

		case x509write_crt_serial_hexadecimal:
			if( ( ret = x509write_crt_set_serial_string(ctx, 16, mandatory->serial_string) ) )
			{
				return ret;
			}
			break;

		case x509write_crt_serial_binary:
			if( ( ret = x509write_crt_set_serial_binary(ctx, mandatory->serial_buffer, mandatory->serial_buffer_length) ) )
			{
				return ret;
			}
			break;
	}

	mbedtls_x509write_crt_set_md_alg( ctx, mandatory->md );

	if( optional &&
		optional->x509_version  >= 1 && optional->x509_version  <= 3)
	{
		mbedtls_x509write_crt_set_version( ctx, optional->x509_version - 1 );
	}

	/*
	 * 2. optional parameters
	 */

	mbedtls_printf( "  . Setting certificate validity ..." );
	if((ret = mbedtls_x509write_crt_set_validity( ctx, mandatory->not_before, mandatory->not_after )))
	{
		char buf[256];

		mbedtls_strerror( ret, buf, sizeof(buf) );
		mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_validity "
						"returned -0x%04x - %s\n\n", -ret, buf );
		return ret;
	}
	mbedtls_printf( " ok\n" );

	if( optional && optional->basic_constraints && ctx->version == MBEDTLS_X509_CRT_VERSION_3 )
	{
		mbedtls_printf( "  . Adding the Basic Constraints extension ..." );
		if( (ret = mbedtls_x509write_crt_set_basic_constraints( ctx,
																optional->basic_constraints->is_ca,
																optional->basic_constraints->max_pathlen )) )
		{
			char buf[256];

			mbedtls_strerror( ret, buf, sizeof(buf) );
			mbedtls_printf( " failed\n  !  x509write_crt_set_basic_contraints "
							"returned -0x%04x - %s\n\n", -ret, buf );
			return ret;
		}

		mbedtls_printf( " ok\n" );
	}
#if defined(MBEDTLS_SHA1_C)
	if( optional && optional->set_subject_key_identifier && ctx->version == MBEDTLS_X509_CRT_VERSION_3 )
	{
		mbedtls_printf( "  . Adding the Subject Key Identifier ..." );

		if( ( ret = mbedtls_x509write_crt_set_subject_key_identifier( ctx ) ) )
		{
			char buf[256];

			mbedtls_strerror( ret, buf, sizeof(buf) );
			mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_subject"
							"_key_identifier returned -0x%04x - %s\n\n",
							-ret, buf );
			return ret;
		}

		mbedtls_printf( " ok\n" );
	}

	if( optional && optional->set_authority_key_identifier && ctx->version == MBEDTLS_X509_CRT_VERSION_3 )
	{
		mbedtls_printf( "  . Adding the Authority Key Identifier ..." );

		if( ( ret = mbedtls_x509write_crt_set_authority_key_identifier( ctx ) ) )
		{
			char buf[256];

			mbedtls_strerror( ret, buf, sizeof(buf) );
			mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_authority_"
							"key_identifier returned -0x%04x - %s\n\n",
							-ret, buf );
			return ret;
		}

		mbedtls_printf( " ok\n" );
	}
#endif // #if defined(MBEDTLS_SHA1_C)
	if( optional && optional->extension_key_usage_flags && ctx->version == MBEDTLS_X509_CRT_VERSION_3 )
	{
		mbedtls_printf( "  . Adding the Key Usage extension ..." );

		if( ( ret = mbedtls_x509write_crt_set_key_usage( ctx, *optional->extension_key_usage_flags ) ) )
		{
			char buf[256];

			mbedtls_strerror( ret, buf, sizeof(buf) );
			mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_key_usage "
							"returned -0x%04x - %s\n\n", -ret, buf );
			return ret;
		}

		mbedtls_printf( " ok\n" );
	}

	if( optional && optional->extension_ns_cert_type_flags && ctx->version == MBEDTLS_X509_CRT_VERSION_3 )
	{

		mbedtls_printf( "  . Adding the NS Cert Type extension ..." );
		if( ( ret = mbedtls_x509write_crt_set_ns_cert_type( ctx, *optional->extension_ns_cert_type_flags ) ) )
		{
			char buf[256];

			mbedtls_strerror( ret, buf, sizeof(buf) );
			mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_set_ns_cert_type "
							"returned -0x%04x - %s\n\n", -ret, buf );
			return ret;
		}

		mbedtls_printf( " ok\n" );
	}
	return 0;
}

int x509write_crt_pem
	(
		mbedtls_x509write_cert *ctx,
		unsigned char *buffer, int length,
		size_t *olen
	)
{
#define PEM_BEGIN_CRT           "-----BEGIN CERTIFICATE-----\n"
#define PEM_END_CRT             "-----END CERTIFICATE-----\n"
	int ret;
	size_t oolen;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *pers = "crt random";

	mbedtls_ctr_drbg_init( &ctr_drbg );
	mbedtls_entropy_init( &entropy );

	mbedtls_printf( "  . Seeding the random number generator..." );
	if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
							   (const unsigned char *) pers,
							   strlen( pers ) ) ) != 0 )
	{
		mbedtls_strerror( ret, (char *)buffer, length );
		mbedtls_printf( " failed\n  !  mbedtls_ctr_drbg_seed -0x%04x - %s\n\n",
						-ret, buffer );
		goto exit;
	}
	mbedtls_printf( " ok\n" );

	mbedtls_printf( "  . Writing the certificate..." );

	if( ( ret = mbedtls_x509write_crt_der( 	ctx, buffer, length,
											mbedtls_ctr_drbg_random, &ctr_drbg ) ) < 0 )
	{
		mbedtls_strerror( ret, (char *)buffer, length );
		mbedtls_printf( " failed\n  !  mbedtls_x509write_crt_der -0x%04x - %s\n\n",
						-ret, buffer );
		goto exit;
	}

	memset( buffer, 0, length - ret);
	if( ( ret = mbedtls_pem_write_buffer( PEM_BEGIN_CRT, PEM_END_CRT,
								  &buffer[length-ret], ret,
								  buffer, length - ret, &oolen ) ) != 0 )
	{
		mbedtls_strerror( ret, (char *)buffer, length );
		mbedtls_printf( " failed\n  !  mbedtls_pem_write_buffer -0x%04x - %s\n\n",
						-ret, buffer );
		goto exit;
	}
	mbedtls_printf( " ok (pem size: %u)\n", oolen );

	if(olen)
	{
		// exclude null character
		*olen = oolen - 1;
	}

exit:
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );
	return( ret );
}

int x509write_crt_der
	(
		mbedtls_x509write_cert *ctx,
		unsigned char *buffer, int length
	)
{
	int ret;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *pers = "crt random";

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

	mbedtls_printf( "  . Writing the certificate..." );
	memset( buffer, 0, length );
	if( ( ret = mbedtls_x509write_crt_der( ctx, buffer, length, mbedtls_ctr_drbg_random, &ctr_drbg ) ) < 0 )
	{
		mbedtls_strerror( ret, (char *)buffer, length );
		mbedtls_printf( " failed\n  !  write_certificate -0x%04x - %s\n\n",
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
int x509write_crt_pem_file
	(
		mbedtls_x509write_cert *ctx,
		const char *output_file
	)
{
    int ret;
    FILE *f;
    unsigned char output_buf[4096];
    size_t len = 0;

    if( ( ret = x509write_crt_pem( ctx, output_buf, 4096, NULL ) ) < 0 )
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
