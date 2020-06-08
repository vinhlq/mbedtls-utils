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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "mbedtls_utils_platform.h"


/*******************************************************************************
* API Constants
*******************************************************************************/

/*******************************************************************************
*   Function Code
*******************************************************************************/

#if 1
int mbedtls_util_write_file(const char *path, uint32_t offset,
							const uint8_t *buf, uint32_t length,
							bool append)
{
	FILE *f;
	uint32_t bytes_written;

	if(append)
	{
		f = fopen( path, "ab" );
	}
	else
	{
		f = fopen( path, "wb+" );
	}

	if(f == NULL)
	{
		return -1;
	}

	fseek( f, offset, SEEK_SET );
	if( offset != ftell( f ))
	{
		goto error;
	}


	bytes_written = fwrite(buf, 1, length, f);
	if(bytes_written != length)
	{
		goto error;
	}
	printf( "  . write: %d(bytes), %d(bytes) written\n", length, bytes_written);

	if(fclose(f))
	{
		return -1;
	}
	else
	{
		return 0;
	}

error:
	fclose(f);
	return -1;
}

int mbedtls_util_read_file(	const char *path,
							uint32_t offset,
							uint8_t *buf,
							uint32_t length,
							uint32_t *read_length)
{
	int ret;
	FILE *f;
	struct stat fstats;

	ret = stat(path, &fstats);
	if (ret || fstats.st_size == 0)
	{
		return -1;
	}

	f = fopen( path, "rb" );
	if(f == NULL)
	{
		return -1;
	}

	fseek( f, offset, SEEK_SET );
	if( offset != ftell( f ))
	{
		goto error;
	}

	*read_length = fread(buf, 1, length, f);
	if(!(*read_length))
	{
		goto error;
	}

	if(fclose(f))
	{
		return -1;
	}
	else
	{
		return 0;
	}

error:
	fclose(f);
	return -1;
}
#endif

/****************************End of File***************************************/
