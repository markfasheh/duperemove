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
#include <errno.h>
#include <pthread.h>

#include "csum.h"
#include "debug.h"

#define	HASH_FUNC	GCRY_MD_SHA256

GCRY_THREAD_OPTION_PTHREAD_IMPL;

#define	HASH_TYPE_SHA256	"SHA256  "


static void sha256_checksum_block(char *buf, int len, unsigned char *digest)
{
	gcry_md_hash_buffer(HASH_FUNC, digest, buf, len);
}

static int sha256_init_hash(unsigned int *ret_digest_len)
{
	gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);

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

	*ret_digest_len = gcry_md_get_algo_dlen(HASH_FUNC);
	if (!(*ret_digest_len))
		return 1;

	return 0;
}

struct sha256_running_checksum {
	gcry_md_hd_t	hd;
	unsigned char	digest[DIGEST_LEN_MAX];
};
DECLARE_RUNNING_CSUM_CAST_FUNCS(sha256_running_checksum);

static struct running_checksum *sha256_start_running_checksum(void)
{
	struct sha256_running_checksum *c =
		calloc(1, sizeof(struct sha256_running_checksum));

	if (c) {
		if (gcry_md_open(&c->hd, HASH_FUNC, 0) != GPG_ERR_NO_ERROR) {
			free(c);
			c = NULL;
		}
	}

	return priv_to_rc(c);
}

static void sha256_add_to_running_checksum(struct running_checksum *_c,
					   unsigned int len, unsigned char *buf)
{
	struct sha256_running_checksum *c = rc_to_priv(_c);
	gcry_md_write(c->hd, buf, len);
}

static void sha256_finish_running_checksum(struct running_checksum *_c,
					   unsigned char *digest)
{
	struct sha256_running_checksum *c = rc_to_priv(_c);
	unsigned char *gcry_digest;

	/* gcry_md_read() does this implicitly */
	gcry_md_final(c->hd);
	gcry_digest = gcry_md_read(c->hd, 0);
	memcpy(digest, gcry_digest, digest_len);

	gcry_md_close(c->hd);

	free(c);
}

struct csum_module_ops ops_sha256 = {
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
