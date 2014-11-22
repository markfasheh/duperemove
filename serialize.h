/*
 * serialize.h
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

#ifndef __SERIALIZE__
#define __SERIALIZE__

#define HASH_FILE_MAJOR	1
#define HASH_FILE_MINOR	1

#define HASH_FILE_MAGIC		"dupehash"
struct hash_file_header {
/*00*/	char		magic[8];
	uint64_t	major;
	uint64_t	minor;
	uint64_t	num_files;
/*20*/	uint64_t	num_hashes;
	uint32_t	block_size; /* In bytes */
	uint32_t	pad0;
	char		hash_type[8];
	uint64_t	pad1[9];
};

#define DISK_DIGEST_LEN		32

struct block_hash {
	uint64_t	loff;
	uint32_t	flags;
	uint32_t	pad[2];
	char		digest[DISK_DIGEST_LEN];
};

struct file_info {
/*00*/	uint64_t	ino;
	uint64_t	file_size;
	uint64_t	num_blocks;
	uint16_t	rec_len;
	uint16_t	name_len;
	uint32_t	pad0;
	uint64_t	subvolid;
/*20*/	uint64_t	pad1[2];
	char		name[0];
};

int serialize_hash_tree(char *filename, struct hash_tree *tree,
			unsigned int block_size);

#define	FILE_VERSION_ERROR	1001
#define	FILE_MAGIC_ERROR	1002
#define	FILE_HASH_TYPE_ERROR	1003
extern char unknown_hash_type[8];
int read_hash_tree(char *filename, struct hash_tree *tree,
		   unsigned int *block_size, struct hash_file_header *ret_hdr,
		   int ignore_hash_type);

#endif /* __SERIALIZE__ */
