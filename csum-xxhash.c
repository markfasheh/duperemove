/*
 * csum.c
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

/*
 * xxhash don't support big hash size (64bit or 32bit supported only) -> split
 * input array in severals and summ out hashs
 */

inline int init_hash(void){return 0;}
uint32_t digest_len = DIGEST_LEN_MAX;

void debug_print_digest(FILE *stream, unsigned char *digest)
{
	uint32_t i;

	for (i = 0; i < DIGEST_LEN_MAX; i++)
		fprintf(stream, "%.2x", digest[i]);
}

#define FACTOR DIGEST_LEN_MAX/__SIZEOF_POINTER__

/* #if __SIZEOF_POINTER__ == 8 */
#if 1
#define XXH XXH64
#define XXH_state_t XXH64_state_t
#define XXH_update XXH64_update
#define XXH_digest XXH64_digest
#else
#define XXH XXH32
#define XXH_state_t XXH32_state_t
#define XXH_update XXH32_update
#define XXH_digest XXH32_digest
#endif

void checksum_block(char *buf, int len, unsigned char *digest) {
	unsigned long long *hash = (unsigned long long *)digest;
	unsigned i;
	char *current = buf;
	for (i=0;i<FACTOR;i++) {
		size_t offset = len/FACTOR*(i+1);
		hash[i] = XXH(current, offset, 0);
		current += offset;
	}
}

struct running_checksum {
	XXH_state_t	td[FACTOR];
};

struct running_checksum *start_running_checksum(void)
{
	struct running_checksum *c = calloc(1, sizeof(struct running_checksum));
	memset(c, 0, sizeof(struct running_checksum));
	return c;
}

void add_to_running_checksum(struct running_checksum *c, unsigned int len, unsigned char *buf)
{
	unsigned i;
	unsigned char *current = buf;
	for (i=0;i<FACTOR;i++) {
		size_t offset = len/FACTOR*(i+1);
		XXH_update (&c->td[i], current, offset);
		current += offset;
	}
}

void finish_running_checksum(struct running_checksum *c, unsigned char *digest)
{
	size_t *hash = (size_t *)digest;
	unsigned i;
	for (i=0;i<FACTOR;i++) {
		hash[i]=XXH_digest (&c->td[i]);
	}
	free(c);
}
