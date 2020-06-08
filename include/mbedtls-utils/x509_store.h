/**
 * \file rsa.h
 *
 * \brief This file provides an API for the RSA public-key cryptosystem.
 *
 * The RSA public-key cryptosystem is defined in <em>Public-Key
 * Cryptography Standards (PKCS) #1 v1.5: RSA Encryption</em>
 * and <em>Public-Key Cryptography Standards (PKCS) #1 v2.1:
 * RSA Cryptography Specifications</em>.
 *
 */
/*
 *  Copyright (C) 2006-2018, Arm Limited (or its affiliates), All Rights Reserved
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
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */
#ifndef TLS_STORE_H
#define TLS_STORE_H
#include <stdbool.h>
//#if !defined(MBEDTLS_CONFIG_FILE)
//#include "config.h"
//#else
//#include MBEDTLS_CONFIG_FILE
//#endif

#ifdef __cplusplus
extern "C" {
#endif


int tls_store_read(	const char *path,
					uint8_t *buf,
					uint32_t offset,
					uint32_t *length);


/**
 * \brief          qca_tls_store_ecc_cert
 *
 * \param type      The destination context. This must be initialized.
 * \param sub_type      The source context. This must be initialized.
 * \param label      The source context. This must be initialized.
 *
 * \return         \c 0 on success.
 */
int qca_tls_store_ecc_cert
(
	mbedtls_ecp_group_id group_id,
	const char *subject_name, mbedtls_x509_crt *issuer_crt, mbedtls_pk_context *issuer_key,
	const char *key_path, const char *crt_path,
	const x509write_crt_mandatory *mandatory, const x509write_crt_optional *optional
);

/**
 * \brief          This function copies the components of an RSA context.
 *
 * \param dst      The destination context. This must be initialized.
 * \param src      The source context. This must be initialized.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory allocation failure.
 */
int x509store_write_aws_ecc_cert
(
	mbedtls_ecp_group_id group_id,
	const char *subject_name, mbedtls_x509_crt *issuer_crt, mbedtls_pk_context *issuer_key,
	const char *ca_cert_pem, uint32_t ca_cert_pem_size,
	const char *key_path, const char *crt_path,
	const x509write_crt_mandatory *mandatory, const x509write_crt_optional *optional
);

int x509store_write_aws_rsa_cert
(
	const char *subject_name, mbedtls_x509_crt *issuer_crt, mbedtls_pk_context *issuer_key,
	const char *ca_cert_pem, uint32_t ca_cert_pem_size,
	const char *key_path, const char *crt_path,
	const x509write_crt_mandatory *mandatory, const x509write_crt_optional *optional
);

/**
 * \brief          This function copies the components of an RSA context.
 *
 * \param dst      The destination context. This must be initialized.
 * \param src      The source context. This must be initialized.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory allocation failure.
 */
int x509store_load_pair_from_file
(
	const char *key_path, const char *crt_path,
	mbedtls_pk_context *key, mbedtls_x509_crt *crt
);
int x509store_check_pair_from_file(const char *key_path, const char *crt_path);

int x509store_load_pair_from_pem(	const char *key_pem, uint32_t key_pem_size,
										const char *crt_pem, uint32_t crt_pem_size,
										mbedtls_pk_context *key, mbedtls_x509_crt *crt);
int x509store_check_pair_from_pem(	const char *key_pem, uint32_t key_pem_size,
										const char *crt_pem, uint32_t crt_pem_size);

int mbedtls_util_write_file(	const char *path,
							uint32_t offset,
							const uint8_t *buf,
							uint32_t length,
							bool append);
#define mbedtls_util_write_pem_file(path, pem, size)	\
		mbedtls_util_write_file(path, 0, pem, size, false)

int mbedtls_util_read_file(	const char *path,
							uint32_t offset,
							uint8_t *buf,
							uint32_t length,
							uint32_t *read_length);
#define mbedtls_util_read_pem_file(path, pem, length, read_length)	\
		mbedtls_util_read_file(path, 0, pem, length, read_length)

#ifdef __cplusplus
}
#endif

#endif /* rsa.h */
