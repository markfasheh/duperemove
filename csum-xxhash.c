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
#include "util.h"

#define XXH_STATIC_LINKING_ONLY
#define XXH_INLINE_ALL

#include "xxhash.h"

static void xxhash_checksum_block(char *buf, int len, unsigned char *digest) {
	XXH128_hash_t hash = XXH128(buf, len, 0);

	((uint64_t*)digest)[0] = hash.low64;
	((uint64_t*)digest)[1] = hash.high64;
}

struct xxhash_running_checksum {
	XXH3_state_t *state;
};
DECLARE_RUNNING_CSUM_CAST_FUNCS(xxhash_running_checksum);

static struct running_checksum *xxhash_start_running_checksum(void)
{
	struct xxhash_running_checksum *c =
		calloc(1, sizeof(struct xxhash_running_checksum));
	c->state = XXH3_createState();
	XXH3_128bits_reset(c->state);
	return priv_to_rc(c);
}

static void xxhash_add_to_running_checksum(struct running_checksum *_c,
					   unsigned int len, unsigned char *buf)
{
	struct xxhash_running_checksum *c = rc_to_priv(_c);
	XXH3_128bits_update(c->state, buf, len);
}

static void xxhash_finish_running_checksum(struct running_checksum *_c,
					   unsigned char *digest)
{
	_cleanup_(freep) struct xxhash_running_checksum *c = rc_to_priv(_c);

	XXH128_hash_t hash = XXH3_128bits_digest(c->state);

	((uint64_t*)digest)[0] = hash.low64;
	((uint64_t*)digest)[1] = hash.high64;
	XXH3_freeState(c->state);
}

static struct csum_module_ops ops_xxhash = {
	.checksum_block		= xxhash_checksum_block,
	.start_running_checksum	= xxhash_start_running_checksum,
	.add_to_running_checksum	= xxhash_add_to_running_checksum,
	.finish_running_checksum	= xxhash_finish_running_checksum,
};

struct csum_module csum_module_xxhash =	{
	.ops = &ops_xxhash,
};
