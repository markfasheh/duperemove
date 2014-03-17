/*
 * csum.c
 *
 * Copyright (C) 2014 SUSE.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>

#include "csum.h"

#define	HASH_FUNC	GCRY_MD_SHA256

unsigned int digest_len = 0;

void checksum_block(char *buf, int len, unsigned char *digest)
{
	gcry_md_hash_buffer(HASH_FUNC, digest, buf, len);
}

int init_hash(void)
{
	/*
	 * Version check should be the very first call because it makes sure
	 * that important subsystems are intialized.
	 */
	if (!gcry_check_version(GCRYPT_VERSION))
		return 1;

	/* Disable secure memory.  */
	gcry_control(GCRYCTL_DISABLE_SECMEM, 0);

	/* Tell Libgcrypt that initialization has completed. */
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

	if (gcry_md_test_algo(HASH_FUNC))
		return 1;

	digest_len = gcry_md_get_algo_dlen(HASH_FUNC);
	if (!digest_len)
		return 1;

	if (digest_len == 0 || digest_len > DIGEST_LEN_MAX)
		abort();

	return 0;
}

void debug_print_digest(FILE *stream, unsigned char *digest)
{
	int i;

	for (i = 0; i < digest_len; i++)
		fprintf(stream, "%.2x", digest[i]);
}

struct running_checksum {
	gcry_md_hd_t	hd;
	unsigned char	digest[DIGEST_LEN_MAX];
};

struct running_checksum *start_running_checksum(void)
{
	struct running_checksum *c = calloc(1, sizeof(struct running_checksum));

	if (c) {	
		if (gcry_md_open(&c->hd, HASH_FUNC, 0) != GPG_ERR_NO_ERROR) {
			free(c);
			c = NULL;
		}
	}

	return c;
}

void add_to_running_checksum(struct running_checksum *c,
			     unsigned int len, unsigned char *buf)
{
	gcry_md_write(c->hd, buf, len);
}

void finish_running_checksum(struct running_checksum *c, unsigned char *digest)
{
	unsigned char *gcry_digest;

	/* gcry_md_read() does this implicitly */
	gcry_md_final(c->hd);
	gcry_digest = gcry_md_read(c->hd, 0);
	memcpy(digest, gcry_digest, digest_len);

	gcry_md_close(c->hd);

	free(c);
}
