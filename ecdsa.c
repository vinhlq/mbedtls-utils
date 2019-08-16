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
#error "MBEDTLS_X509_CSR_WRITE_C and/or "	\
            "MBEDTLS_PK_PARSE_C and/or MBEDTLS_SHA256_C and/or "	\
            "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C "	\
            "not defined.\n"
#endif

#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rsa.h"

#ifdef MBEDTLS_FS_IO
static int write_private_key_pem
	(
		mbedtls_pk_context *key,
		const char *output_file
	)
{
    int ret;
    FILE *f;
    unsigned char output_buf[16000];
    size_t len = 0;

    memset(output_buf, 0, 16000);

	if( ( ret = mbedtls_pk_write_key_pem( key, output_buf, 16000 ) ) != 0 )
		return( ret );

	len = strlen( (char *) output_buf );

    if( ( f = fopen( output_file, "wb" ) ) == NULL )
        return( -1 );

    if( fwrite( output_buf, 1, len, f ) != len )
    {
        fclose( f );
        return( -1 );
    }

    fclose( f );

    return( 0 );
}

static int write_private_key_der
	(
		mbedtls_pk_context *key,
		const char *output_file
	)
{
    int ret;
    FILE *f;
    unsigned char output_buf[16000];
    unsigned char *c = output_buf;
    size_t len = 0;

    memset(output_buf, 0, 16000);
    /**
    *                  Note: data is written at the end of the buffer! Use the
    *                        return value to determine where you should start
    *                        using the buffer
    */
	if( ( ret = mbedtls_pk_write_key_der( key, output_buf, sizeof(output_buf) ) ) < 0 )
		return( ret );

	len = ret;
	c = output_buf + sizeof(output_buf) - len;

    if( ( f = fopen( output_file, "wb" ) ) == NULL )
        return( -1 );

    if( fwrite( c, 1, len, f ) != len )
    {
        fclose( f );
        return( -1 );
    }

    fclose( f );

    return( 0 );
}

static int write_public_key_pem
	(
		mbedtls_pk_context *key,
		const char *output_file
	)
{
    int ret;
    FILE *f;
    unsigned char output_buf[16000];
    size_t len = 0;

    memset(output_buf, 0, 16000);
#if defined(MBEDTLS_PEM_WRITE_C)
	if( ( ret = mbedtls_pk_write_pubkey_pem( key, output_buf, 16000 ) ) != 0 )
		return( ret );

	len = strlen( (char *) output_buf );
#endif

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

static int write_public_key_der
	(
		mbedtls_pk_context *key,
		const char *output_file
	)
{
    int ret;
    FILE *f;
    unsigned char output_buf[16000];
    unsigned char *c = output_buf;
    size_t len = 0;

    memset(output_buf, 0, 16000);

    /**
	*                  Note: data is written at the end of the buffer! Use the
	*                        return value to determine where you should start
	*                        using the buffer
	*/
	if( ( ret = mbedtls_pk_write_pubkey_der( key, output_buf, 16000 ) ) < 0 )
		return( ret );

	len = ret;
	c = output_buf + sizeof(output_buf) - len;

    if( ( f = fopen( output_file, "w" ) ) == NULL )
        return( -1 );

    if( fwrite( c, 1, len, f ) != len )
    {
        fclose( f );
        return( -1 );
    }

    fclose( f );

    return( 0 );
}

int ecdsa_write_pem(
		mbedtls_pk_context *ctx,
		const char *private_key_output_file,
		const char *public_key_output_file)
{
	int ret = 1;

	if(private_key_output_file)
	{
		if( ( ret = write_private_key_pem( ctx, private_key_output_file ) ) != 0 )
			return( ret );
	}

	if(public_key_output_file)
	{
		if( ( ret = write_public_key_pem( ctx, public_key_output_file ) ) != 0 )
			return( ret );
	}

	return ( ret );
}

int ecdsa_write_der(
		mbedtls_pk_context *ctx,
		const char *private_key_output_file,
		const char *public_key_output_file)
{
	int ret = 1;

	if(private_key_output_file)
	{
		if( ( ret = write_private_key_der( ctx, private_key_output_file ) ) != 0 )
			return( ret );
	}

	if(public_key_output_file)
	{
		if( ( ret = write_public_key_der( ctx, public_key_output_file ) ) != 0 )
			return( ret );
	}

	return ( ret );
}
#endif

static void dump_buf( const char *title, unsigned char *buf, size_t len )
{
    size_t i;

    mbedtls_printf( "%s", title );
    for( i = 0; i < len; i++ )
        mbedtls_printf("%c%c", "0123456789ABCDEF" [buf[i] / 16],
                       "0123456789ABCDEF" [buf[i] % 16] );
    mbedtls_printf( "\n" );
}

static void dump_pubkey( const char *title, mbedtls_ecdsa_context *key )
{
    unsigned char buf[300];
    size_t len;

    if( mbedtls_ecp_point_write_binary( &key->grp, &key->Q,
                MBEDTLS_ECP_PF_UNCOMPRESSED, &len, buf, sizeof buf ) != 0 )
    {
        mbedtls_printf("internal error\n");
        return;
    }

    dump_buf( title, buf, len );
}

int ecdsa_gen_key1(mbedtls_pk_context *ctx, mbedtls_ecp_group_id group_id)
{
	int ret = 1;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ecdsa_context *ecdsa;
	const char *pers = "ecdsa random seed";
//	mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;

	mbedtls_ctr_drbg_init( &ctr_drbg );
	mbedtls_entropy_init( &entropy );

	mbedtls_printf( "  . Initialise ECDSA context..." );
	if( ( ret = mbedtls_pk_setup(ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECDSA)) ) != 0 )
	{
		mbedtls_printf( " failed\n  !  mbedtls_pk_setup returned -0x%04x", -ret );
		goto exit;
	}
	mbedtls_printf( " ok\n" );

	ecdsa = (mbedtls_ecdsa_context *)ctx->pk_ctx;
//	mbedtls_ecdsa_init(ecdsa);

	mbedtls_printf( "  . Seeding the random number generator..." );
	if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
							   (const unsigned char *) pers,
							   strlen( pers ) ) ) != 0 )
	{
		mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
		goto exit;
	}
	mbedtls_printf( " ok\n" );

	mbedtls_printf( " ok\n  . Generating key pair..." );
	if( ( ret = mbedtls_ecdsa_genkey( ecdsa, group_id, mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
	{
		mbedtls_printf( " failed\n  ! mbedtls_ecdsa_genkey returned %d\n", ret );
		goto exit;
	}
	mbedtls_printf( " ok (key size: %d bits)\n", (int) ecdsa->grp.pbits );

	dump_pubkey( "  + Public key: ", ecdsa );
exit:
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );
//	mbedtls_ecdsa_free(ecdsa);
	return( ret );
}
