/*
 * csum-sha256.c
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
#include <errno.h>
#include <pthread.h>

#include "sha256.h"

#include "csum.h"
#include "debug.h"

#define	HASH_TYPE_SHA256	"SHA256  "
#define DIGEST_LEN_SHA256	32

static void sha256_checksum_block(char *buf, int len, unsigned char *digest)
{
	sha256((unsigned char *)buf, len, digest, 0);
}

static int sha256_init_hash(unsigned int *ret_digest_len)
{
	*ret_digest_len = DIGEST_LEN_SHA256;

	return 0;
}

struct sha256_running_checksum {
	sha256_context	ctx;
};
DECLARE_RUNNING_CSUM_CAST_FUNCS(sha256_running_checksum);

static struct running_checksum *sha256_start_running_checksum(void)
{
	struct sha256_running_checksum *c =
		calloc(1, sizeof(struct sha256_running_checksum));

	if (c) {
		sha256_init(&c->ctx);
		sha256_starts(&c->ctx, 0);
	}
	return priv_to_rc(c);
}

static void sha256_add_to_running_checksum(struct running_checksum *_c,
					   unsigned int len, unsigned char *buf)
{
	struct sha256_running_checksum *c = rc_to_priv(_c);

	sha256_update(&c->ctx, buf, len);
}

static void sha256_finish_running_checksum(struct running_checksum *_c,
					   unsigned char *digest)
{
	struct sha256_running_checksum *c = rc_to_priv(_c);

	sha256_finish(&c->ctx, digest);
	sha256_free(&c->ctx);
	free(c);
}

static struct csum_module_ops ops_sha256 = {
	.init			= sha256_init_hash,
	.checksum_block		= sha256_checksum_block,
	.start_running_checksum	= sha256_start_running_checksum,
	.add_to_running_checksum	= sha256_add_to_running_checksum,
	.finish_running_checksum	= sha256_finish_running_checksum,
};

struct csum_module csum_module_sha256 =	{
	.name = "SHA256",
	.hash_type = HASH_TYPE_SHA256,
	.ops = &ops_sha256,
};
