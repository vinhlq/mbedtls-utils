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
#ifndef TLS_X509_CRT_H
#define TLS_X509_CRT_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct{
	mbedtls_pk_context *pk;
	const char *name;
}x509write_crt_subject;

typedef enum {
	x509write_crt_serial_decimal,
	x509write_crt_serial_hexadecimal,
	x509write_crt_serial_binary
}x509write_crt_serial_type;

typedef struct
{
	const char *not_before;
	const char *not_after;
	mbedtls_md_type_t md;
	mbedtls_pk_context *issuer_key;
	x509write_crt_serial_type serial_type;
	union {
		const char *serial_string;
		struct {
			unsigned char *serial_buffer;
			int serial_buffer_length;
		};
	};
}x509write_crt_mandatory;

typedef struct {
	int is_ca;
	int max_pathlen;
}x509write_crt_extension_basic_constraints;

typedef struct
{
	int x509_version;
	x509write_crt_extension_basic_constraints *basic_constraints;
	char set_subject_key_identifier;
	char set_authority_key_identifier;

	// MBEDTLS_X509_KU_DIGITAL_SIGNATURE
	// MBEDTLS_X509_KU_NON_REPUDIATION
	// MBEDTLS_X509_KU_KEY_ENCIPHERMENT
	// MBEDTLS_X509_KU_DATA_ENCIPHERMENT
	// MBEDTLS_X509_KU_KEY_AGREEMENT
	// MBEDTLS_X509_KU_KEY_CERT_SIGN
	// MBEDTLS_X509_KU_CRL_SIGN
	unsigned char *extension_key_usage_flags;

	// MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT
	// MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER
	// MBEDTLS_X509_NS_CERT_TYPE_EMAIL
	// MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING
	// MBEDTLS_X509_NS_CERT_TYPE_SSL_CA
	// MBEDTLS_X509_NS_CERT_TYPE_EMAIL_CA
	// MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING_CA
	unsigned char *extension_ns_cert_type_flags;
}x509write_crt_optional;

typedef enum {
	x509write_crt_set_md_alg,
	x509write_crt_set_version,
	x509write_crt_set_validity,
	x509write_crt_set_extension_basic_constraints,


	x509write_crt_set_extension_key_usage_flags,


	x509write_crt_set_extension_ns_cert_type_flags,
	x509write_crt_set_subject_key_identifier,
	x509write_crt_set_authority_identifier
}x509write_crt_set_params;

typedef struct {
	const char *not_before;
	const char *not_after;
}x509write_crt_validity;

/**
 * \brief          This function copies the components of an RSA context.
 *
 * \param dst      The destination context. This must be initialized.
 * \param src      The source context. This must be initialized.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory allocation failure.
 */
int x509write_crt_set_issuer(mbedtls_x509write_cert *ctx, mbedtls_pk_context *issuer_key, const char *issuer_name);

/**
 * \brief          This function copies the components of an RSA context.
 *
 * \param dst      The destination context. This must be initialized.
 * \param src      The source context. This must be initialized.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory allocation failure.
 */
int x509write_crt_set_subject(mbedtls_x509write_cert *ctx, mbedtls_pk_context *subject_key, const char *subject_name);

/**
 * \brief          This function copies the components of an RSA context.
 *
 * \param dst      The destination context. This must be initialized.
 * \param src      The source context. This must be initialized.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory allocation failure.
 */
int x509write_crt_set_subject_from_csr(mbedtls_x509write_cert *ctx, mbedtls_x509_csr *csr);

/**
 * \brief          This function copies the components of an RSA context.
 *
 * \param dst      The destination context. This must be initialized.
 * \param src      The source context. This must be initialized.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory allocation failure.
 */
int x509write_crt_set_serial_decimal_string(mbedtls_x509write_cert *ctx, const char *serial);

/**
 * \brief          This function copies the components of an RSA context.
 *
 * \param dst      The destination context. This must be initialized.
 * \param src      The source context. This must be initialized.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory allocation failure.
 */
int x509write_crt_setup(mbedtls_x509write_cert *ctx,
						x509write_crt_subject *subject, mbedtls_x509_crt *issuer_crt, mbedtls_pk_context *issuer_key,
						const x509write_crt_mandatory *mandatory, const x509write_crt_optional *optional);

/**
 * \brief          This function copies the components of an RSA context.
 *
 * \param dst      The destination context. This must be initialized.
 * \param src      The source context. This must be initialized.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory allocation failure.
 */
int x509write_crt_write_pem_buffer( mbedtls_x509write_cert *ctx, unsigned char *buffer, int length, size_t *olen);

/**
 * \brief          This function copies the components of an RSA context.
 *
 * \param dst      The destination context. This must be initialized.
 * \param src      The source context. This must be initialized.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory allocation failure.
 */
int x509write_crt_write_der_buffer( mbedtls_x509write_cert *ctx, unsigned char *buffer, int length);

/**
 * \brief          This function copies the components of an RSA context.
 *
 * \param dst      The destination context. This must be initialized.
 * \param src      The source context. This must be initialized.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory allocation failure.
 */
int x509write_crt_write_pem( mbedtls_x509write_cert *ctx, const char *output_file);



int x509_crt_fingerprint_sha1(const unsigned char *pem, size_t size, unsigned char out[20]);
int x509_crt_fingerprint_sha256(const unsigned char *pem, size_t size, unsigned char out[32]);
int x509_crt_fingerprint_sha256_hex(const unsigned char *pem, size_t size, unsigned char *buffer, size_t length);
int x509_crt_fingerprint_sha1_hex(const unsigned char *pem, size_t size, unsigned char *buffer, size_t length);


#ifdef __cplusplus
}
#endif

#endif /* rsa.h */
