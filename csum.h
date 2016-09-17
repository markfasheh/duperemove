/*
 * csum.h
 *
 * Copyright (C) 2016 SUSE.  All rights reserved.
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

#ifndef __CSUM_H__
#define __CSUM_H__

#include <stdio.h>

#define	DIGEST_LEN_MAX	32
#define DEFAULT_HASH_STR	"murmur3"

extern unsigned int digest_len;
extern char hash_type[8];

/* Init / debug */
int init_csum_module(const char *type);
void debug_print_digest_len(FILE *stream, unsigned char *digest, int len);
static inline void debug_print_digest(FILE *stream, unsigned char *digest)
{
	debug_print_digest_len(stream, digest, digest_len);
}
static inline void debug_print_digest_short(FILE *stream, unsigned char *digest)
{
	debug_print_digest_len(stream, digest, 4);
}

/* Checksums a single block in one go. */
void checksum_block(char *buf, int len, unsigned char *digest);

/* Keeping a 'running' checksum - we add data to it a bit at a time */
struct running_checksum;
struct running_checksum *start_running_checksum(void);
void add_to_running_checksum(struct running_checksum *c,
			     unsigned int len, unsigned char *buf);
void finish_running_checksum(struct running_checksum *c, unsigned char *digest);

/* csum-module implementation details */

struct csum_module_ops {
	int (*init)(unsigned int *ret_digest_len);
	void (*checksum_block)(char *buf, int len, unsigned char *digest);
	struct running_checksum *(*start_running_checksum)(void);
	void (*add_to_running_checksum)(struct running_checksum *c,
					unsigned int len, unsigned char *buf);
	void (*finish_running_checksum)(struct running_checksum *c,
					unsigned char *digest);
};

struct csum_module {
	/*
	 * Friendly name, suitable for printing to the user. We use
	 * this also for option parsing.
	 */
	const char *name;

	/*
	 * Internally identifies this hash, is also what we write in
	 * hashfiles. Must not exceed 8 characters.
	 */
	const char *hash_type;
	struct csum_module_ops *ops;
};

extern struct csum_module csum_module_xxhash;
extern struct csum_module csum_module_murmur3;

extern struct csum_module *csum_mod; /* The module currently in use */

#define	DECLARE_RUNNING_CSUM_CAST_FUNCS(_type)				\
static inline struct _type *						\
rc_to_priv(struct running_checksum *rc)					\
{									\
	return (struct _type *)rc;					\
}									\
static inline struct running_checksum *					\
priv_to_rc(struct _type *priv)						\
{									\
	return (struct running_checksum *)priv;				\
}

#endif	/* csum.h */
