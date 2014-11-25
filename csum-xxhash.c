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

#define		HASH_TYPE	"XXHASH  "
char hash_type[8];
uint32_t digest_len = DIGEST_LEN_MAX;

int init_hash(void)
{
	strncpy(hash_type, HASH_TYPE, 8);
	return 0;
}

void debug_print_digest(FILE *stream, unsigned char *digest)
{
	uint32_t i;

	for (i = 0; i < DIGEST_LEN_MAX; i++)
		fprintf(stream, "%.2x", digest[i]);
}

void checksum_block(char *buf, int len, unsigned char *digest) {
	unsigned long long d;

	d = XXH64(buf, len, 0);
	memcpy(digest, &d, sizeof(d));
}

struct running_checksum {
	XXH64_state_t	td64;
};

struct running_checksum *start_running_checksum(void)
{
	struct running_checksum *c = calloc(1, sizeof(struct running_checksum));
	memset(c, 0, sizeof(struct running_checksum));
	XXH64_reset(&c->td64, 0);
	return c;
}

void add_to_running_checksum(struct running_checksum *c, unsigned int len, unsigned char *buf)
{
	XXH64_update(&c->td64, buf, len);
}

void finish_running_checksum(struct running_checksum *c, unsigned char *digest)
{
	unsigned long long d = XXH64_digest(&c->td64);
	memcpy(digest, &d, sizeof(d));
	free(c);
}
