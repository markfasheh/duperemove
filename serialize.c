/*
 * serialize.c
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stddef.h>
#include <limits.h>
#include <endian.h>
#include <byteswap.h>

#include "kernel.h"
#include "rbtree.h"
#include "list.h"
#include "debug.h"

#include "csum.h"
#include "filerec.h"
#include "hash-tree.h"

#include "serialize.h"

char unknown_hash_type[8];
#define	hash_type_v1_0	"\0\0\0\0\0\0\0\0"

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define swap16(_x)	((uint16_t)_x)
#define swap32(_x)	((uint32_t)_x)
#define swap64(_x)	((uint64_t)_x)
#elif __BYTE_ORDER == __BIG_ENDIAN
#define swap16(_x)	((uint16_t)bswap_16(_x))
#define swap32(_x)	((uint32_t)bswap_32(_x))
#define swap64(_x)	((uint64_t)bswap_64(_x))
#else
#error Invalid byte order __BYTE_ORDER
#endif

static void debug_print_header(struct hash_file_header *h)
{
	dprintf("Disk Header Info: [ ");
	dprintf("magic: %.*s\t", 8, h->magic);
	dprintf("major: %"PRIu64"\t", h->major);
	dprintf("minor: %"PRIu64"\t", h->minor);
	dprintf("num_files: %"PRIu64"\t", h->num_files);
	dprintf("num_hashes: %"PRIu64"\t", h->num_hashes);
	dprintf("block_size: %u\t", h->block_size);
	dprintf("hash_type: %.*s\t", 8, h->hash_type);
	dprintf(" ]\n");
}

static void debug_print_file_info(struct file_info *f)
{
	unsigned int name_len = swap16(f->name_len);

	dprintf("Disk File Info: [ ");
	dprintf("ino: %"PRIu64"\t", swap64(f->ino));
	dprintf("file_size: %"PRIu64"\t", swap64(f->file_size));
	dprintf("num_blocks: %"PRIu64"\t", swap64(f->num_blocks));
	dprintf("rec_len: %u\t", swap16(f->rec_len));
	dprintf("name_len: %u\t", name_len);
	dprintf("name: \"%.*s\"\t", name_len, f->name);
	dprintf(" ]\n");
}

static int write_header(int fd, struct hash_file_header *h)
{
	int written;
	loff_t ret;
	struct hash_file_header disk;

	memset(&disk, 0, sizeof(struct hash_file_header));

	memcpy(disk.magic, HASH_FILE_MAGIC, 8);
	disk.major = swap64(HASH_FILE_MAJOR);
	disk.minor = swap64(HASH_FILE_MINOR);
	disk.num_files = swap64(h->num_files);
	disk.num_hashes = swap64(h->num_hashes);
	disk.block_size = swap32(h->block_size);
	memcpy(&disk.hash_type, hash_type, 8);

	ret = lseek(fd, 0, SEEK_SET);
	if (ret == (loff_t)-1)
		return errno;
	written = write(fd, &disk, sizeof(struct hash_file_header));
	if (written == -1)
		return errno;
	if (written != sizeof(struct hash_file_header))
		return EIO;

	return 0;
}

static int write_file_info(int fd, struct filerec *file)
{
	int written, name_len;
	struct file_info finfo = { 0, };
	char *n;

	finfo.ino = swap64(file->inum);
	finfo.file_size = 0ULL; /* We don't store this yet */
	finfo.num_blocks = swap64(file->num_blocks);
	finfo.subvolid = swap64(file->subvolid);

	name_len = strlen(file->filename);
	finfo.name_len = swap16(name_len);
	finfo.rec_len = swap16(name_len + sizeof(struct file_info));

	written = write(fd, &finfo, sizeof(struct file_info));
	if (written == -1)
		return errno;
	if (written != sizeof(struct file_info))
		return EIO;

	n = file->filename;

	written = write(fd, n, name_len);
	if (written == -1)
		return errno;
	if (written != name_len)
		return EIO;

	return 0;
}

static int write_one_hash(int fd, struct file_block *block)
{
	int written;
	struct block_hash disk_block = { 0, };

	disk_block.loff = swap64(block->b_loff);
	disk_block.flags = swap32(block->b_flags);
	BUILD_BUG_ON(DISK_DIGEST_LEN < DIGEST_LEN_MAX);
	memcpy(&disk_block.digest, block->b_parent->dl_hash, DISK_DIGEST_LEN);

	written = write(fd, &disk_block, sizeof(struct block_hash));
	if (written == -1)
		return errno;
	if (written != sizeof(struct block_hash))
		return EIO;

	return 0;
}

int serialize_hash_tree(char *filename, struct hash_tree *tree,
			unsigned int block_size)
{
	int ret, fd;
	struct hash_file_header *h = calloc(1, sizeof(*h));
	struct filerec *file;
	struct file_block *block;
	uint64_t tot_files, tot_hashes;

	if (!h)
		return ENOMEM;

	fd = open(filename, O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (fd == -1) {
		ret = errno;
		free(h);
		return ret;
	}

	/* Write the header first with zero files */
	h->block_size = block_size;
	write_header(fd, h);

	tot_files = tot_hashes = 0;
	list_for_each_entry(file, &filerec_list, rec_list) {
		if (list_empty(&file->block_list))
			continue;

		ret = write_file_info(fd, file);
		if (ret)
			goto out;
		tot_files++;

		/* Now write each one of this files hashes */
		list_for_each_entry(block, &file->block_list, b_file_next) {
			tot_hashes++;
			ret = write_one_hash(fd, block);
			if (ret)
				goto out;
		}
	}

	/* When we're done, rewrite the header */
	h->num_files = tot_files;
	h->num_hashes = tot_hashes;
	ret = write_header(fd, h);

out:
	free(h);
	close(fd);
	return ret;
}

static int read_file(int fd, struct file_info *f, char *fname)
{
	int ret, name_len;
	struct file_info disk;

	ret = read(fd, &disk, sizeof(struct file_info));
	if (ret == -1)
		return errno;
	if (ret < sizeof(struct file_info)) {
		/* We reached EOF when we expected to have more files
		 * to read in */
		return EIO;
	}
	name_len = swap16(disk.name_len);

	ret = read(fd, fname, name_len);
	if (ret == -1)
		return errno;
	if (ret != name_len)
		return EIO;

	fname[name_len] = '\0';

	f->ino = swap64(disk.ino);
	f->file_size = swap64(disk.file_size);
	f->num_blocks = swap64(disk.num_blocks);
	f->subvolid = swap64(disk.subvolid);
	f->rec_len = swap16(disk.rec_len);
	f->name_len = swap16(disk.name_len);

	return 0;
}

static int read_hash(int fd, struct block_hash *b)
{
	int ret;
	struct block_hash disk;

	ret = read(fd, &disk, sizeof(struct block_hash));
	if (ret == -1)
		return errno;
	if (ret != sizeof(struct block_hash))
		return EIO;

	b->loff = swap64(disk.loff);
	b->flags = swap32(disk.flags);
	memcpy(b->digest, disk.digest, DISK_DIGEST_LEN);
	return 0;
}

static int read_one_file(int fd, struct hash_tree *tree)
{
	int ret;
	uint32_t i;
	struct file_info finfo;
	struct block_hash bhash;
	struct filerec *file;
	char fname[PATH_MAX+1];

	ret = read_file(fd, &finfo, fname);
	if (ret)
		return ret;

	dprintf("Load %"PRIu64" hashes for \"%s\"\n", finfo.num_blocks,
		fname);

	file = filerec_new(fname, finfo.ino, finfo.subvolid);
	if (file == NULL)
		return ENOMEM;

	for (i = 0; i < finfo.num_blocks; i++) {
		ret = read_hash(fd, &bhash);
		if (ret)
			return ret;

		ret = insert_hashed_block(tree, (unsigned char *)bhash.digest,
					  file, bhash.loff, bhash.flags);
		if (ret)
			return ENOMEM;
	}

	return 0;
}

static int read_header(int fd, struct hash_file_header *h)
{
	int ret;
	struct hash_file_header disk;

	ret = read(fd, &disk, sizeof(struct hash_file_header));
	if (ret == -1)
		return errno;
	if (ret != sizeof(struct hash_file_header))
		return EIO;

	memcpy(h->magic, disk.magic, 8);
	h->major = swap64(disk.major);
	h->minor = swap64(disk.minor);
	h->num_files = swap64(disk.num_files);
	h->num_hashes = swap64(disk.num_hashes);
	h->block_size = swap32(disk.block_size);
	memcpy(&h->hash_type, &disk.hash_type, 8);

	return 0;
}

int read_hash_tree(char *filename, struct hash_tree *tree,
		   unsigned int *block_size, struct hash_file_header *ret_hdr,
		   int ignore_hash_type)
{
	int ret, fd;
	uint32_t i;
	struct hash_file_header h;

	fd = open(filename, O_RDONLY);
	if (fd == -1)
		return errno;

	ret = read_header(fd, &h);
	if (ret)
		return ret;

	debug_print_header(&h);
	if (memcmp(h.magic, HASH_FILE_MAGIC, 8)) {
		ret = FILE_MAGIC_ERROR;
		goto out;
	}
	if (h.major > HASH_FILE_MAJOR) {
		ret = FILE_VERSION_ERROR;
		goto out;
	}

	if (!ignore_hash_type) {
		/*
		 * v1.0 hash files were SHA256 but wrote out hash_type
		 * as nulls
		 */
		if (h.minor == 0 && memcmp(hash_type_v1_0, h.hash_type, 8)) {
			ret = FILE_HASH_TYPE_ERROR;
			memcpy(unknown_hash_type, hash_type_v1_0, 8);
			goto out;
		} else  if (h.minor > 0 && memcmp(h.hash_type, hash_type, 8)) {
			ret = FILE_HASH_TYPE_ERROR;
			memcpy(unknown_hash_type, h.hash_type, 8);
			goto out;
		}
	}

	*block_size = h.block_size;

	dprintf("Load %"PRIu64" files from \"%s\"\n",
		h.num_files, filename);

	for (i = 0; i < h.num_files; i++) {
		ret = read_one_file(fd, tree);
		if (ret)
			break;
	}
out:
	if (ret == 0 && ret_hdr)
		memcpy(ret_hdr, &h, sizeof(struct hash_file_header));
	return ret;
}
