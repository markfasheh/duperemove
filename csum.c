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

struct csum_module *csum_mod = &csum_module_xxhash;

void debug_print_digest_len(FILE *stream, unsigned char *digest, unsigned int len)
{
	uint32_t i;

	abort_on(len > DIGEST_LEN);

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
