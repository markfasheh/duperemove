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

/*
 * This implementation is based on the work from https://github.com/PeterScott/murmur3
 */


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <string.h>

#include "csum.h"
#include "debug.h"

#define		HASH_TYPE       "Murmur3 "
char		hash_type[8];
unsigned int	digest_len = 0;

#ifdef __GNUC__
#define FORCE_INLINE __attribute__((always_inline)) inline
#else
#define FORCE_INLINE inline
#endif

static FORCE_INLINE uint32_t rotl32(uint32_t x,int8_t r)
{
	return (x << r) | (x >> (32 - r));
}

static FORCE_INLINE uint64_t rotl64(uint64_t x,int8_t r)
{
	return (x << r) | (x >> (64 - r));
}

#define ROTL32(x,y)     rotl32(x,y)
#define ROTL64(x,y)     rotl64(x,y)

#define BIG_CONSTANT(x) (x##LLU)

#define getblock(p, i) (p[i])

static FORCE_INLINE uint32_t fmix32(uint32_t h)
{
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;

	return h;
}

static FORCE_INLINE uint64_t fmix64(uint64_t k)
{
	k ^= k >> 33;
	k *= BIG_CONSTANT(0xff51afd7ed558ccd);
	k ^= k >> 33;
	k *= BIG_CONSTANT(0xc4ceb9fe1a85ec53);
	k ^= k >> 33;

	return k;
}

int init_hash(void)
{
	strncpy(hash_type, HASH_TYPE, 8);
	digest_len = 16;
	abort_on(digest_len == 0 || digest_len > DIGEST_LEN_MAX);
	return 0;
}

void debug_print_digest(FILE *stream, unsigned char *digest)
{
	uint32_t i;

	for (i = 0; i < digest_len; i++)
		fprintf(stream, "%.2x", digest[i]);
}

void checksum_block(char *buf, int len, unsigned char *digest)
{
	struct running_checksum *csum = start_running_checksum();
	add_to_running_checksum(csum, len, (unsigned char*)buf);
	finish_running_checksum(csum, digest);
}

struct running_checksum {
	uint64_t	h1;
	uint64_t	h2;
	uint64_t	len;
	unsigned char rem_buffer[32]; /* Won't be bigger than 16 * 2*/
	unsigned int rem_len;
};

struct running_checksum *start_running_checksum(void)
{
	struct running_checksum *c = calloc(1, sizeof(struct running_checksum));

	if (c) {
		/* Init h1 & h2 with the same seed */
		c->h1 = 42;
		c->h2 = 42;
		c->len = 0;
		c->rem_len = 0;
		memset(c->rem_buffer, 0, 32);
	}

	return c;
}

void add_to_running_checksum(struct running_checksum *c,
			     unsigned int len, unsigned char *buf)
{
	const uint8_t * data = (const uint8_t*)buf;
	const int nblocks = len / 16;

	c->len += nblocks * 16;

	int i;

	uint64_t c1 = BIG_CONSTANT(0x87c37b91114253d5);
	uint64_t c2 = BIG_CONSTANT(0x4cf5ad432745937f);

	const uint64_t * blocks = (const uint64_t *)(data);

	for (i = 0; i < nblocks; i++) {
		uint64_t k1 = blocks[i * 2];
		uint64_t k2 = blocks[i * 2 + 1];

		k1 *= c1;
		k1 = ROTL64(k1, 31);
		k1 *= c2;
		c->h1 ^= k1;

		c->h1 = ROTL64(c->h1, 27);
		c->h1 += c->h2;
		c->h1 = c->h1 * 5 + 0x52dce729;

		k2 *= c2;
		k2 = ROTL64(k2, 33);
		k2 *= c1;
		c->h2 ^= k2;

		c->h2 = ROTL64(c->h2, 31);
		c->h2 += c->h1;
		c->h2 = c->h2 * 5 + 0x38495ab5;
	}

	for(i = nblocks * 16; i < len; i++){
		c->rem_buffer[c->rem_len] = buf[i];
		c->rem_len++;
	}
	c->rem_buffer[c->rem_len] = '\0';

	if(c->rem_len >= 16){
		c->rem_len -= 16;

                /* recursive call won't write the c->rem* members
                 * we are sending a single16-bytes block
                 */
		add_to_running_checksum(c, 16, c->rem_buffer);
		c->rem_buffer[c->rem_len] = '\0';
	}
}

void checksum_tailing_data(struct running_checksum *c)
{
	uint64_t c1 = BIG_CONSTANT(0x87c37b91114253d5);
	uint64_t c2 = BIG_CONSTANT(0x4cf5ad432745937f);

	const uint8_t * tail = c->rem_buffer;

	uint64_t k1 = 0;
	uint64_t k2 = 0;

	switch(c->len & 15){
	case 15:
		k2 ^= (uint64_t)(tail[14]) << 48;
	case 14:
		k2 ^= (uint64_t)(tail[13]) << 40;
	case 13:
		k2 ^= (uint64_t)(tail[12]) << 32;
	case 12:
		k2 ^= (uint64_t)(tail[11]) << 24;
	case 11:
		k2 ^= (uint64_t)(tail[10]) << 16;
	case 10:
		k2 ^= (uint64_t)(tail[ 9]) << 8;
	case  9:
		k2 ^= (uint64_t)(tail[ 8]) << 0;
		k2 *= c2;
		k2 = ROTL64(k2, 33);
		k2 *= c1;
		c->h2 ^= k2;

	case  8:
		k1 ^= (uint64_t)(tail[ 7]) << 56;
	case  7:
		k1 ^= (uint64_t)(tail[ 6]) << 48;
	case  6:
		k1 ^= (uint64_t)(tail[ 5]) << 40;
	case  5:
		k1 ^= (uint64_t)(tail[ 4]) << 32;
	case  4:
		k1 ^= (uint64_t)(tail[ 3]) << 24;
	case  3:
		k1 ^= (uint64_t)(tail[ 2]) << 16;
	case  2:
		k1 ^= (uint64_t)(tail[ 1]) << 8;
	case  1:
		k1 ^= (uint64_t)(tail[ 0]) << 0;
		k1 *= c1;
		k1 = ROTL64(k1, 31);
		k1 *= c2;
		c->h1 ^= k1;
	};
}


void finish_running_checksum(struct running_checksum *c, unsigned char *digest)
{
	if(c->rem_len != 0)
		checksum_tailing_data(c);

	uint64_t h1 = c->h1;
	uint64_t h2 = c->h2;
	uint64_t len = c->len;

	h1 ^= len;
	h2 ^= len;

	h1 += h2;
	h2 += h1;

	h1 = fmix64(h1);
	h2 = fmix64(h2);

	h1 += h2;
	h2 += h1;

	((uint64_t*)digest)[0] = h1;
	((uint64_t*)digest)[1] = h2;

	memset(&digest[digest_len], 0, DIGEST_LEN_MAX - digest_len);

	free(c);
}
