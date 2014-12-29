/*
 * csum-xxhash.c
 *
 * Copyright (C) 2013 SUSE.  All rights reserved.
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
#include <stddef.h>
#include <string.h>

#include "csum.h"
#include "debug.h"
#include "xxhash.h"

#define		HASH_TYPE_XXHASH	"XXHASH  "

static int xxhash_init_hash(unsigned int *ret_digest_len)
{
	*ret_digest_len = DIGEST_LEN_MAX;
	return 0;
}

static void xxhash_checksum_block(char *buf, int len, unsigned char *digest) {
	unsigned long long *hash = (unsigned long long*)digest;
	/*
	 * For xxhash one use only first 64 bit from 256 bit hash field
	 * Zeroing empty 192 bits with offset
	 */
	memset(&hash[1], 0, DIGEST_LEN_MAX-sizeof(*hash));
	*hash = XXH64(buf, len, 0);
}

struct xxhash_running_checksum {
	XXH64_state_t	td64;
};
DECLARE_RUNNING_CSUM_CAST_FUNCS(xxhash_running_checksum);

static struct running_checksum *xxhash_start_running_checksum(void)
{
	struct xxhash_running_checksum *c =
		calloc(1, sizeof(struct xxhash_running_checksum));
	XXH64_reset(&c->td64, 0);
	return priv_to_rc(c);
}

static void xxhash_add_to_running_checksum(struct running_checksum *_c,
					   unsigned int len, unsigned char *buf)
{
	struct xxhash_running_checksum *c = rc_to_priv(_c);
	XXH64_update(&c->td64, buf, len);
}

static void xxhash_finish_running_checksum(struct running_checksum *_c,
					   unsigned char *digest)
{
	struct xxhash_running_checksum *c = rc_to_priv(_c);
	unsigned long long *hash = (unsigned long long*)digest;

	*hash = XXH64_digest(&c->td64);
	free(c);
}

static struct csum_module_ops ops_xxhash = {
	.init			= xxhash_init_hash,
	.checksum_block		= xxhash_checksum_block,
	.start_running_checksum	= xxhash_start_running_checksum,
	.add_to_running_checksum	= xxhash_add_to_running_checksum,
	.finish_running_checksum	= xxhash_finish_running_checksum,
};

struct csum_module csum_module_xxhash =	{
	.name = "xxhash",
	.hash_type = HASH_TYPE_XXHASH,
	.ops = &ops_xxhash,
};
