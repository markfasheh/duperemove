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

#include "csum.h"
#include "debug.h"
#include "util.h"

#define XXH_STATIC_LINKING_ONLY
#define XXH_INLINE_ALL
#include "xxhash.h"

struct xxhash_running_checksum {
        XXH3_state_t *state;
};
DECLARE_RUNNING_CSUM_CAST_FUNCS(xxhash_running_checksum);

void debug_print_digest_len(FILE *stream, unsigned char *digest, unsigned int len)
{
	uint32_t i;

	abort_on(len > DIGEST_LEN);

	for (i = 0; i < len; i++)
		fprintf(stream, "%.2x", digest[i]);
}

void checksum_block(char *buf, int len, unsigned char *digest)
{
	XXH128_hash_t hash = XXH128(buf, len, 0);

	((uint64_t*)digest)[0] = hash.low64;
	((uint64_t*)digest)[1] = hash.high64;
}

struct running_checksum *start_running_checksum(void)
{
	struct xxhash_running_checksum *c =
		calloc(1, sizeof(struct xxhash_running_checksum));
	c->state = XXH3_createState();
	XXH3_128bits_reset(c->state);
	return priv_to_rc(c);
}

void add_to_running_checksum(struct running_checksum *_c,
			     unsigned char *buf, unsigned int len)
{
	struct xxhash_running_checksum *c = rc_to_priv(_c);
	XXH3_128bits_update(c->state, buf, len);
}

void finish_running_checksum(struct running_checksum *_c, unsigned char *digest)
{
	_cleanup_(freep) struct xxhash_running_checksum *c = rc_to_priv(_c);

	XXH128_hash_t hash = XXH3_128bits_digest(c->state);

	if (digest) {
		((uint64_t*)digest)[0] = hash.low64;
		((uint64_t*)digest)[1] = hash.high64;
	}
	XXH3_freeState(c->state);
}
