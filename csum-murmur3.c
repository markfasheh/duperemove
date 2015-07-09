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
#include "util.h"
#include "debug.h"

#define		HASH_TYPE_MURMUR3       "Murmur3 "

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

static int murmur3_init_hash(unsigned int *ret_digest_len)
{
	*ret_digest_len = 16;
	return 0;
}

#define	REM_BUFFER_LEN	15

struct murmur3_running_checksum {
	uint64_t	h1;
	uint64_t	h2;
	uint64_t	len;
	unsigned char rem_buffer[REM_BUFFER_LEN]; /* Holds partial block between calls */
	unsigned int rem_len;
};
DECLARE_RUNNING_CSUM_CAST_FUNCS(murmur3_running_checksum);

static struct running_checksum *murmur3_start_running_checksum(void)
{
	struct murmur3_running_checksum *c =
		calloc(1, sizeof(struct murmur3_running_checksum));

	if (c) {
		/* Init h1 & h2 with the same seed */
		c->h1 = 42;
		c->h2 = 42;
		c->len = 0;
		c->rem_len = 0;
	}

	return priv_to_rc(c);
}

static void murmur3_add_to_running_checksum(struct running_checksum *_c,
					    unsigned int len,
					    unsigned char *buf)
{
	struct murmur3_running_checksum *c = rc_to_priv(_c);
	unsigned char block[16];
	const uint8_t * data = (const uint8_t*)buf;
	int i;

	uint64_t c1 = BIG_CONSTANT(0x87c37b91114253d5);
	uint64_t c2 = BIG_CONSTANT(0x4cf5ad432745937f);

	abort_on(c->rem_len > REM_BUFFER_LEN);

	/* Process pending data first */
	if(c->rem_len + len >= 16 && c->rem_len != 0){
		memcpy(block, c->rem_buffer, c->rem_len);
		for(i = 0; i < (16 - c->rem_len); i++)
			block[c->rem_len + i] = data[i];
		data = data + (16 - c->rem_len);
		len -= (16 - c->rem_len);
		c->rem_len = 0;
		add_to_running_checksum(_c, 16, block);
	}

	/* We will now process 16-bytes blocks, as much as possible */
	while(len >= 16){
		uint64_t k1, k2;

		memcpy(&k1, data, sizeof(k1));
		memcpy(&k2, data + sizeof(k1), sizeof(k2));

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

		/* Move the cursor to process the next block */
		data += 16;
		c->len += 16;
		len -= 16;
	}

	/* We will concat instead of just copy
	 * we can update multiple too-low blocks in a row
	 */
	abort_on((c->rem_len + len) > REM_BUFFER_LEN);
	memcpy(&c->rem_buffer[c->rem_len], data, len);
	c->rem_len += len;
}

static void checksum_tailing_data(struct murmur3_running_checksum *c)
{
	uint64_t c1 = BIG_CONSTANT(0x87c37b91114253d5);
	uint64_t c2 = BIG_CONSTANT(0x4cf5ad432745937f);

	const uint8_t * tail = c->rem_buffer;
	c->len += c->rem_len;

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


static void murmur3_finish_running_checksum(struct running_checksum *_c,
					    unsigned char *digest)
{
	struct murmur3_running_checksum *c = rc_to_priv(_c);

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

static void murmur3_checksum_block(char *buf, int len, unsigned char *digest)
{
	struct running_checksum *csum = murmur3_start_running_checksum();
	murmur3_add_to_running_checksum(csum, len, (unsigned char*)buf);
	murmur3_finish_running_checksum(csum, digest);
}


static struct csum_module_ops ops_murmur3 = {
	.init			= murmur3_init_hash,
	.checksum_block		= murmur3_checksum_block,
	.start_running_checksum	= murmur3_start_running_checksum,
	.add_to_running_checksum	= murmur3_add_to_running_checksum,
	.finish_running_checksum	= murmur3_finish_running_checksum,
};

struct csum_module csum_module_murmur3 =	{
	.name = "murmur3",
	.hash_type = HASH_TYPE_MURMUR3,
	.ops = &ops_murmur3,
};
