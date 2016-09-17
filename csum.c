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
#include <errno.h>
#include <string.h>
#include <strings.h>

#include "csum.h"
#include "debug.h"

unsigned int	digest_len = 0;
char		hash_type[8];

static struct csum_module *modules[] = {
	&csum_module_murmur3,
	&csum_module_xxhash,
	NULL,
};

struct csum_module *csum_mod = NULL;

int init_csum_module(const char *type)
{
	int ret;
	struct csum_module *m = modules[0];
	int i = 0;

	while (m) {
		if (strcasecmp(type, m->name) == 0)
			break;
		m = modules[++i];
	}

	if (!m)
		return EINVAL;

	csum_mod = m;
	strncpy(hash_type, csum_mod->hash_type, 8);

	ret = csum_mod->ops->init(&digest_len);
	if (ret)
		return ret;

	abort_on(digest_len == 0 || digest_len > DIGEST_LEN_MAX);

	return 0;
}

void debug_print_digest_len(FILE *stream, unsigned char *digest, int len)
{
	uint32_t i;

	abort_on(len > digest_len);

	for (i = 0; i < len; i++)
		fprintf(stream, "%.2x", digest[i]);
}

void checksum_block(char *buf, int len, unsigned char *digest)
{
	csum_mod->ops->checksum_block(buf, len, digest);
}

struct running_checksum *start_running_checksum(void)
{
	return csum_mod->ops->start_running_checksum();
}

void add_to_running_checksum(struct running_checksum *c,
			     unsigned int len, unsigned char *buf)
{
	csum_mod->ops->add_to_running_checksum(c, len, buf);
}

void finish_running_checksum(struct running_checksum *c, unsigned char *digest)
{
	csum_mod->ops->finish_running_checksum(c, digest);
}
