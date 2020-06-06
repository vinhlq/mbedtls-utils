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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>

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

#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/ecp.h"
#include "mbedtls/error.h"

#include "mbedtls-utils/ecp.h"
#include "mbedtls-utils/x509_csr.h"
#include "mbedtls-utils/x509_crt.h"

#include "mbedtls_utils_platform.h"
#include "mbedtls-utils/x509_store.h"

#define TLS_ESP_PARTITION_TYPE ESP_PARTITION_TYPE_DATA
//#define TLS_ESP_PARTITION_TYPE ESP_PARTITION_TYPE_APP
#ifdef CONFIG_ENABLE_FLASH_ENCRYPT
#error "need to disable CONFIG_ENABLE_FLASH_ENCRYPT"
#endif

#define mbedtls_printfln(fmt,args...)			mbedtls_printf(fmt "%s", ## args, "\r\n")
#ifdef ESP_TLS_STORE_DEBUG_ENABLED
static const char *TAG = "esp-tls-store";
#define debugPrintln	mbedtls_printfln
#else
#define debugPrintln(...)
#endif

#define PEM_BUFFER_SIZE	(3072)



int qca_x509store_ecc_cert
(
	mbedtls_ecp_group_id group_id,
	const char *subject_name, mbedtls_x509_crt *issuer_crt, mbedtls_pk_context *issuer_key,
	const char *key_path, const char *crt_path,
	const x509write_crt_mandatory *mandatory, const x509write_crt_optional *optional
)
{
	int ret;

	x509write_crt_subject subject;
	mbedtls_pk_context subject_key;
    mbedtls_x509write_cert x509write_crt_ctx;
	unsigned char *pem_buf;
	size_t olen;

	pem_buf = malloc(PEM_BUFFER_SIZE);
	if(!pem_buf)
	{
		return -1;
	}
	mbedtls_pk_init( &subject_key );
	mbedtls_x509write_crt_init( &x509write_crt_ctx );

	mbedtls_printf( "  . Generate the subject key ..." );
	if( ( ret = ecp_gen_key(&subject_key, group_id) ) )
		goto exit;
	memset(pem_buf, 0, PEM_BUFFER_SIZE);
	if( ( ret = mbedtls_pk_write_key_pem( &subject_key, pem_buf, PEM_BUFFER_SIZE ) ) != 0 )
		goto exit;
	mbedtls_printf("%s\n", pem_buf);
	mbedtls_printf( " ok\n" );

	if( ( ret = mbedtls_util_write_file(key_path, 0, pem_buf, strlen((const char *)pem_buf), false) ) )
	{
		goto exit;
	}

//	memset(pem_buf, 0, PEM_BUFFER_SIZE);
//	qca_x509store_partition_read(x509store->label, x509store->key_offset, pem_buf, PEM_BUFFER_SIZE);
//	mbedtls_printf("%s\n", pem_buf);
#if 0
	debugPrintln
		(
			"%s",
			(const char *)qca_x509store_get_rom_address
				(
					x509store->type,
					x509store->sub_type,
					x509store->label,
					x509store->key_offset
				)
		);
#else
	debugPrintln
			(
				"%.*s",
				olen, pem_buf
			);
#endif


	subject.name = subject_name;
	subject.pk = &subject_key;
    if( ( ret = x509write_crt_setup(&x509write_crt_ctx,
    								&subject, issuer_crt, issuer_key,
    								mandatory, optional) ) )
    {
    	goto exit;
    }

	if( ( ret = x509write_crt_write_pem_buffer(&x509write_crt_ctx, pem_buf, PEM_BUFFER_SIZE, &olen) ) )
	{
		goto exit;
	}

	if( ( ret = mbedtls_util_write_file(crt_path, 0, pem_buf, strlen((const char *)pem_buf), false) ) )
	{
		goto exit;
	}

//	mbedtls_printf("%s\n", pem_buf);

#if 0
	debugPrintln
		(
			"%s",
			(const char *)qca_x509store_get_rom_address
				(
					x509store->type, x509store->sub_type,
					x509store->label,
					x509store->crt_offset
				)
		);
#else
	debugPrintln
			(
				"%.*s",
				olen, pem_buf
			);
#endif
	mbedtls_printf( " ok\n" );

exit:
	mbedtls_pk_free( &subject_key );
	mbedtls_x509write_crt_free( &x509write_crt_ctx );
	free(pem_buf);
	return ret;
}

int x509store_write_aws_ecc_cert
(
	mbedtls_ecp_group_id group_id,
	const char *subject_name, mbedtls_x509_crt *issuer_crt, mbedtls_pk_context *issuer_key,
	const char *root_ca_pem,
	const char *key_path, const char *crt_path,
	const x509write_crt_mandatory *mandatory, const x509write_crt_optional *optional
)
{
	int ret;
	x509write_crt_subject subject;
	mbedtls_pk_context subject_key;
    mbedtls_x509write_cert x509write_crt_ctx;
	unsigned char *pem_buf;
	uint32_t len, olen;

	pem_buf = malloc(PEM_BUFFER_SIZE);
	if(!pem_buf)
	{
		mbedtls_printf( "  . Memory alloc is failed\n" );
		return -1;
	}
	mbedtls_pk_init( &subject_key );
	mbedtls_x509write_crt_init( &x509write_crt_ctx );

	mbedtls_printf( "  . Generate the subject key ..." );
	if( ( ret = ecp_gen_key(&subject_key, group_id) ) )
	{
		goto exit;
	}
	memset(pem_buf, 0, PEM_BUFFER_SIZE);
	if( ( ret = mbedtls_pk_write_key_pem( &subject_key, pem_buf, PEM_BUFFER_SIZE ) ) != 0 )
	{
		goto exit;
	}
//	mbedtls_printf("%s\n", pem_buf);
	mbedtls_printf( " ok\n" );

	if( (ret = mbedtls_util_write_file(key_path, 0, pem_buf, strlen((const char *)pem_buf), false) ) )
	{
		mbedtls_printf( "  . write file '%s' failed\n", key_path);
		ret = -1;
		goto exit;
	}

//	mbedtls_printf("%s\n", (const char *)qca_x509store_get_rom_address(x509store->type, x509store->sub_type, x509store->label, x509store->key_offset));


	subject.name = subject_name;
	subject.pk = &subject_key;
    if( ( ret = x509write_crt_setup(&x509write_crt_ctx,
    								&subject, issuer_crt, issuer_key,
    								mandatory, optional) ) )
    {
    	goto exit;
    }

	if( ( ret = x509write_crt_write_pem_buffer(&x509write_crt_ctx, pem_buf, PEM_BUFFER_SIZE, &olen) ) )
	{
		ret = -1;
		goto exit;
	}

	if(olen > 1)
	{
		// exclude null character
		olen -= 1;

#if 0
		struct chunk_arg_s arg1, arg2;
		arg1.buffer = pem_buf;
		arg1.length = olen;
		arg2.buffer = root_ca_pem;
		arg2.length = strlen(root_ca_pem);
#if 1
		if(QAPI_OK != mbedtls_util_write_file_chunk(crt_path, false, 0, 2, &arg1, &arg2))
		{
			mbedtls_printf( "  . Write file '%s' failed...\n", crt_path);
			ret = -1;
			goto exit;
		}
#else
		if(QAPI_OK != mbedtls_util_write_file_chunk(crt_path, false, 0, 1, &arg1))
		{
			mbedtls_printf( "  . Write file '%s' failed...\n", crt_path);
			ret = -1;
			goto exit;
		}
#endif
#else
		if( ( ret = mbedtls_util_write_file(crt_path, 0, pem_buf, olen, false) ) )
		{
			goto exit;
		}

		if( ( ret = mbedtls_util_write_file(crt_path, 0, root_ca_pem, strlen(root_ca_pem), true) ) )
		{
			goto exit;
		}
#endif
	}
	else
	{
		mbedtls_printf( "  . Invalid cert size: %d\n", olen);
		ret = -1;
		goto exit;
	}

//	mbedtls_printf("%s\n", pem_buf);
	mbedtls_printf( " ok\n" );

exit:
	mbedtls_pk_free( &subject_key );
	mbedtls_x509write_crt_free( &x509write_crt_ctx );
	free(pem_buf);
	return ret;
}

int x509store_load_pair_from_pem(	const char *key_pem, uint32_t key_pem_size,
										const char *crt_pem, uint32_t crt_pem_size,
										mbedtls_pk_context *key, mbedtls_x509_crt *crt)
{
	int ret;
	unsigned char *pem_buf;

	pem_buf = malloc(PEM_BUFFER_SIZE);
	if(!pem_buf)
	{
		return -1;
	}

	if( !crt_pem_size || crt_pem_size >= PEM_BUFFER_SIZE )
	{
		mbedtls_printf( "  . Invalid key pem size: %d\n", crt_pem_size);
		goto exit;
	}
	memcpy(pem_buf, crt_pem, crt_pem_size);
	pem_buf[crt_pem_size] = '\0';

	mbedtls_printf( "  . Loading the certificate ..." );
	if( ( ret = mbedtls_x509_crt_parse( crt,
										pem_buf,
										(uint32_t)(crt_pem_size + 1)) ) != 0 )
	{
		mbedtls_strerror( ret, (char *)pem_buf, PEM_BUFFER_SIZE );
		mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse "
						"returned -0x%04x - %s\n\n", -ret, pem_buf );
		goto exit;
	}
	mbedtls_printf( " ok\n" );

	mbedtls_printf( "  . Loading the key ..." );
	if( !key_pem_size || key_pem_size >= PEM_BUFFER_SIZE )
	{
		mbedtls_printf( "  . Invalid key pem size: %d\n", key_pem_size);
		goto exit;
	}
	memcpy(pem_buf, key_pem, key_pem_size);
	pem_buf[key_pem_size] = '\0';

	ret = mbedtls_pk_parse_key
			(
				key,
				pem_buf,
				(uint32_t)(key_pem_size + 1),
				NULL, 0
			);
	if( ret != 0 )
	{
		mbedtls_strerror( ret, (char *)pem_buf, PEM_BUFFER_SIZE );
		mbedtls_printf( " failed\n  !  mbedtls_pk_parse_key "
						"returned -x%02x - %s\n\n", -ret, pem_buf );
		goto exit;
	}
	mbedtls_printf( " ok\n" );

	mbedtls_printf( "  . Check if key and certificate match..." );
	if( (ret = mbedtls_pk_check_pair( &crt->pk, key ) ) != 0 )
	{
		mbedtls_strerror( ret, (char *)pem_buf, PEM_BUFFER_SIZE );
		mbedtls_printf( " failed\n  !  mbedtls_pk_check_pair "
						"returned -0x%04x - %s\n\n", -ret, pem_buf );
	}
	mbedtls_printf( " ok\n" );

exit:
	free(pem_buf);
	return ret;
}

int x509store_load_pair_from_file(	const char *key_path, const char *crt_path,
									mbedtls_pk_context *key, mbedtls_x509_crt *crt)
{
	int ret;
	unsigned char *pem_buf;
	size_t pem_size;

	pem_buf = malloc(PEM_BUFFER_SIZE);
	if(!pem_buf)
	{
		return -1;
	}

	if( (ret = mbedtls_util_read_file(crt_path, 0, pem_buf, PEM_BUFFER_SIZE - 1, &pem_size) ) )
	{
		mbedtls_printf( "  . Read file '%s' failed...\n", crt_path);
		goto exit;
	}

	if(!pem_size)
	{
		mbedtls_printf( "  . Invalid certificate size: %u, copy failed...\n", pem_size);
		ret = -1;
		goto exit;
	}
	pem_buf[pem_size] = '\0';

	mbedtls_printf( "  . Loading the certificate ..." );
	if( ( ret = mbedtls_x509_crt_parse( crt,
										pem_buf,
										(uint32_t)(pem_size + 1)) ) != 0 )
	{
		mbedtls_strerror( ret, (char *)pem_buf, PEM_BUFFER_SIZE );
		mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse "
						"returned -0x%04x - %s\n\n", -ret, pem_buf );
		goto exit;
	}
	mbedtls_printf( " ok\n" );

	mbedtls_printf( "  . Loading the key ..." );
	if( ( ret = mbedtls_util_read_file(key_path, 0, pem_buf, PEM_BUFFER_SIZE - 1, &pem_size) ) )
	{
		goto exit;
	}

	if(!pem_size)
	{
		mbedtls_printf( "  . Invalid key size: %u, copy failed...\n", pem_size);
		ret = -1;
		goto exit;
	}
	pem_buf[pem_size] = '\0';

	ret = mbedtls_pk_parse_key
			(
				key,
				pem_buf,
				(uint32_t)(pem_size + 1),
				NULL, 0
			);
	if( ret != 0 )
	{
		mbedtls_strerror( ret, (char *)pem_buf, PEM_BUFFER_SIZE );
		mbedtls_printf( " failed\n  !  mbedtls_pk_parse_key "
						"returned -x%02x - %s\n\n", -ret, pem_buf );
		goto exit;
	}
	mbedtls_printf( " ok\n" );

	mbedtls_printf( "  . Check if key and certificate match..." );
	if( (ret = mbedtls_pk_check_pair( &crt->pk, key ) ) != 0 )
	{
		mbedtls_strerror( ret, (char *)pem_buf, PEM_BUFFER_SIZE );
		mbedtls_printf( " failed\n  !  mbedtls_pk_check_pair "
						"returned -0x%04x - %s\n\n", -ret, pem_buf );
	}
	mbedtls_printf( " ok\n" );

exit:
	free(pem_buf);
	return ret;
}

int x509store_check_pair_from_file(const char *key_path, const char *crt_path)
{
	mbedtls_pk_context key;
	mbedtls_x509_crt crt;
	int ret;

	mbedtls_pk_init( &key );
	mbedtls_x509_crt_init( &crt );

	ret = x509store_load_pair_from_file(key_path, crt_path, &key, &crt);

	mbedtls_pk_free( &key );
	mbedtls_x509_crt_free( &crt );

	return ret;
}

int x509store_check_pair_from_pem(	const char *key_pem, uint32_t key_pem_size,
										const char *crt_pem, uint32_t crt_pem_size)
{
	mbedtls_pk_context key;
	mbedtls_x509_crt crt;
	int ret;

	mbedtls_pk_init( &key );
	mbedtls_x509_crt_init( &crt );

	ret = x509store_load_pair_from_pem(	key_pem, key_pem_size,
											crt_pem, crt_pem_size,
											&key, &crt);

	mbedtls_pk_free( &key );
	mbedtls_x509_crt_free( &crt );

	return ret;
}

static int pem_persistent_init(const char *path, const char *default_pem)
{

}

int qca_x509store_cert_persistent_init(const char *path, const char *default_pem)
{

}

#ifdef MBEDTLS_FS_IO

#endif

