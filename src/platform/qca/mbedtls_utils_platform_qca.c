/*
 * Copyright (c) 2020 vinhlq.
 * All Rights Reserved.
 */
// Copyright (c) 2020 vinhlq.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without modification, are permitted (subject to the limitations in the disclaimer below)
// provided that the following conditions are met:
// Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
// Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
// Neither the name of Qualcomm Technologies, Inc. nor the names of its contributors may be used to endorse or promote products derived
// from this software without specific prior written permission.
// NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY THIS LICENSE.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
// BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
// OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
// EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

/*******************************************************************************
* Included headers
*******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>

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

#include "qapi_types.h"
#include "qapi_status.h"
#include "qapi_fs.h"

#include "mbedtls_utils_platform.h"

#define PRINTF(...)	printf(__VA_ARGS__)

/*******************************************************************************
* API Constants
*******************************************************************************/

/*******************************************************************************
*   Function Code
*******************************************************************************/

#if 0
struct chunk_arg_s
{
	uint8_t *buffer;
	uint32_t offset;
	uint32_t length;
};

static qapi_Status_t mbedtls_util_write_file_chunk(const char *path, qbool_t append, uint32_t offset, uint32_t count, ...)
{
	int fd;
	qapi_Status_t ret;
	uint32_t bytes_written;
	va_list arg_ptr;

	if(append)
	{
		uint32_t actual_offset;

		ret = qapi_Fs_Open(path, QAPI_FS_O_WRONLY, &fd);
		if(QAPI_OK != ret)
		{
			return ret;
		}

		ret = qapi_Fs_Lseek(fd, offset, QAPI_FS_SEEK_END, &actual_offset);
		if(QAPI_OK != ret)
		{
			goto exit;
		}
		offset = actual_offset;
	}
	else
	{
		uint32_t actual_offset;

		ret = qapi_Fs_Open(path, QAPI_FS_O_WRONLY | QAPI_FS_O_CREAT, &fd);
		if(QAPI_OK != ret)
		{
			return ret;
		}

		ret = qapi_Fs_Lseek(fd, offset, QAPI_FS_SEEK_SET, &actual_offset);
		if(QAPI_OK != ret)
		{
			goto exit;
		}
		offset = actual_offset;
	}

	va_start(arg_ptr, count);
	while(count--)
	{
		struct chunk_arg_s *chunk;

		chunk = va_arg(arg_ptr, struct chunk_arg_s *);
		if(!chunk || !chunk->buffer || !chunk->length)
		{
			mbedtls_printf( "  . Invalid chunk\n");
			ret = QAPI_ERROR;
			break;
		}
		else
		{
			ret = qapi_Fs_Write(fd, chunk->buffer, chunk->length, &bytes_written);
			mbedtls_printf( "  . chunk: %d(bytes), %d(bytes) written\n", chunk->length, bytes_written);
			if(QAPI_OK != ret)
			{
				break;
			}

			if(bytes_written != chunk->length)
			{
				ret = QAPI_ERROR;
				break;
			}
			chunk->offset = offset;
			offset += bytes_written;
		}
	}
	va_end(arg_ptr);

	if(QAPI_OK != ret)
	{
		goto exit;
	}

	return qapi_Fs_Close(fd);

exit:
	qapi_Fs_Close(fd);
	return ret;
}

static qapi_Status_t mbedtls_util_read_file_va_list(const char *path, uint32_t count, ...)
{
	int fd;
	qapi_Status_t ret;
	va_list arg_ptr;
	struct qapi_fs_stat_type fstat;

	ret = qapi_Fs_Open(path, QAPI_FS_O_RDONLY, &fd);
	if(QAPI_OK != ret)
	{
		return ret;
	}

	ret = qapi_Fs_Stat(path, &fstat);
	if (QAPI_OK != ret)
	{
		return ret;
	}

	if (fstat.st_size == 0)
	{
		return QAPI_ERROR;
	}

	va_start(arg_ptr, count);
	while(count--)
	{
		struct chunk_arg_s *chunk;

		chunk = va_arg(arg_ptr, struct chunk_arg_s *);
		if(!chunk || !chunk->buffer || !chunk->length)
		{
			ret = QAPI_ERROR;
			break;
		}
		else
		{
			uint32_t n;

			if ((chunk->offset + chunk->length) < fstat.st_size)
			{
				ret = QAPI_ERROR;
				break;
			}

			ret = qapi_Fs_Lseek(fd, chunk->offset, QAPI_FS_SEEK_SET, &n);
			if(QAPI_OK != ret)
			{
				break;
			}

			if(n != chunk->offset)
			{
				ret = QAPI_ERROR;
				break;
			}

			ret = qapi_Fs_Read(fd, chunk->buffer, chunk->length, &n);
			if(QAPI_OK != ret)
			{
				break;
			}
			chunk->length = n;
		}
	}
	va_end(arg_ptr);

	if(QAPI_OK != ret)
	{
		goto exit;
	}
	return qapi_Fs_Close(fd);
exit:
	qapi_Fs_Close(fd);
	return ret;
}

int mbedtls_util_write_file(	const char *path, uint32_t offset,
							uint8_t *buf, uint32_t length,
							bool append)
{
	struct chunk_arg_s chunk;

	if(!append)
	{
		qapi_Fs_Unlink(path);
	}
	chunk.buffer = buf;
	chunk.length = length;
	if(QAPI_OK == mbedtls_util_write_file_chunk(path, append, offset, 1, &chunk))
	{
		return 0;
	}
	return -1;
}

int mbedtls_util_read_file(	const char *path,
							uint32_t offset,
							uint8_t *buf,
							uint32_t length,
							uint32_t *read_length)
{
	struct chunk_arg_s chunk;
	qapi_Status_t ret;

	chunk.buffer = buf;
	chunk.length = length;
	chunk.offset = offset;
	ret = mbedtls_util_read_file_va_list(path, 1, &chunk);
	*read_length = chunk.length;
	if(QAPI_OK == ret)
	{
		return 0;
	}
	return -1;
}
#else
int mbedtls_util_write_file(	const char *path, uint32_t offset,
							uint8_t *buf, uint32_t length,
							bool append)
{
	int fd;
	qapi_Status_t ret;
	uint32_t bytes_written;

	if(append)
	{
		uint32_t actual_offset;

		ret = qapi_Fs_Open(path, QAPI_FS_O_WRONLY, &fd);
		if(QAPI_OK != ret)
		{
			PRINTF("open: '%s' to write failed: %d\r\n", path, ret);
			return -1;
		}

		ret = qapi_Fs_Lseek(fd, offset, QAPI_FS_SEEK_END, &actual_offset);
		if(QAPI_OK != ret)
		{
			PRINTF("lseek: '%s' to %d: failed: %d\r\n", path, offset, ret);
			goto error;
		}
		offset = actual_offset;
		PRINTF("file: '%s': actual offset: %d\r\n", path, offset);
	}
	else
	{
		uint32_t actual_offset;

		qapi_Fs_Unlink(path);

		ret = qapi_Fs_Open(path, QAPI_FS_O_WRONLY | QAPI_FS_O_CREAT, &fd);
		if(QAPI_OK != ret)
		{
			PRINTF("open: '%s' to write failed: %d\r\n", path, ret);
			return -1;
		}

		ret = qapi_Fs_Lseek(fd, offset, QAPI_FS_SEEK_SET, &actual_offset);
		if(QAPI_OK != ret)
		{
			PRINTF("lseek: '%s' to %d: failed: %d\r\n", path, offset, ret);
			goto error;
		}
		offset = actual_offset;
		PRINTF("file: '%s': actual offset: %d\r\n", path, offset);
	}


	ret = qapi_Fs_Write(fd, buf, length, &bytes_written);
	if(QAPI_OK != ret || bytes_written != length)
	{
		PRINTF("write: '%s': %d(bytes) failed: %d\r\n", path, length, ret);
		goto error;
	}
	PRINTF( "write: %d(bytes), %d(bytes) written\n", length, bytes_written);

	ret = qapi_Fs_Close(fd);
	if(QAPI_OK == ret)
	{
		return 0;
	}
	else
	{
		PRINTF("close: '%s' on write failed: %d\r\n", path, ret);
		return -1;
	}

error:
	qapi_Fs_Close(fd);
	return -1;
}

int mbedtls_util_read_file(	const char *path,
							uint32_t offset,
							uint8_t *buf,
							uint32_t length,
							uint32_t *read_length)
{
	int fd;
	qapi_Status_t ret;
	struct qapi_fs_stat_type fstat;
	uint32_t n;

	ret = qapi_Fs_Stat(path, &fstat);
	if (QAPI_OK != ret || fstat.st_size == 0)
	{
		PRINTF("stat: '%s' failed: %d, st_size: %d\r\n", path, ret, fstat.st_size);
		return -1;
	}

	ret = qapi_Fs_Open(path, QAPI_FS_O_RDONLY, &fd);
	if(QAPI_OK != ret)
	{
		PRINTF("open: '%s' to read failed: %d\r\n", path, ret);
		return -1;
	}

	ret = qapi_Fs_Lseek(fd, offset, QAPI_FS_SEEK_SET, &n);
	if(QAPI_OK != ret || n != offset)
	{
		PRINTF("lseek: '%s' to %d: failed: %d\r\n", path, offset, ret);
		goto error;
	}
	PRINTF("file: '%s': actual offset: %d\r\n", path, n);

	ret = qapi_Fs_Read(fd, buf, length, read_length);
	if(QAPI_OK != ret)
	{
		PRINTF("read: '%s': %d(bytes) failed: %d\r\n", path, length, ret);
		goto error;
	}

	ret = qapi_Fs_Close(fd);
	if(QAPI_OK == ret)
	{
		return 0;
	}
	else
	{
		PRINTF("close: '%s' on read failed: %d\r\n", path, ret);
		return -1;
	}

error:
	qapi_Fs_Close(fd);
	return -1;
}
#endif

/****************************End of File***************************************/
