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

#include "bswap.h"

char unknown_hash_type[8];
#define	hash_type_v1_0	"\0\0\0\0\0\0\0\0"

static void debug_print_header(struct hash_file_header *h)
{
	dprintf("Disk Header Info: [ ");
	dprintf("magic: %.*s\t", 8, h->magic);
	dprintf("major: %"PRIu64"\t", le64_to_cpu(h->major));
	dprintf("minor: %"PRIu64"\t", le64_to_cpu(h->minor));
	dprintf("num_files: %"PRIu64"\t", le64_to_cpu(h->num_files));
	dprintf("num_hashes: %"PRIu64"\t", le64_to_cpu(h->num_hashes));
	dprintf("block_size: %u\t", le32_to_cpu(h->block_size));
	dprintf("hash_type: %.*s\t", 8, h->hash_type);
	dprintf(" ]\n");
}

static void debug_print_file_info(struct file_info *f)
{
	unsigned int name_len = le16_to_cpu(f->name_len);

	dprintf("Disk File Info: [ ");
	dprintf("ino: %"PRIu64"\t", le64_to_cpu(f->ino));
	dprintf("file_size: %"PRIu64"\t", le64_to_cpu(f->file_size));
	dprintf("num_blocks: %"PRIu64"\t", le64_to_cpu(f->num_blocks));
	dprintf("rec_len: %u\t", le16_to_cpu(f->rec_len));
	dprintf("name_len: %u\t", name_len);
	dprintf("name: \"%.*s\"\t", name_len, f->name);
	dprintf(" ]\n");
}

int write_header(int fd, uint64_t num_files, uint64_t num_hashes,
			uint32_t block_size)
{
	int written;
	int ret = 0;
	loff_t err;
	struct hash_file_header *disk = calloc(1, sizeof(*disk));

	if (!disk)
		return ENOMEM;

	memcpy(disk->magic, HASH_FILE_MAGIC, 8);
	disk->major = cpu_to_le64(HASH_FILE_MAJOR);
	disk->minor = cpu_to_le64(HASH_FILE_MINOR);
	disk->num_files = cpu_to_le64(num_files);
	disk->num_hashes = cpu_to_le64(num_hashes);
	disk->block_size = cpu_to_le32(block_size);
	memcpy(disk->hash_type, hash_type, 8);

	err = lseek(fd, 0, SEEK_SET);
	if (err == (loff_t)-1) {
		ret = errno;
		goto out;
	}

	written = write(fd, disk, sizeof(struct hash_file_header));
	if (written == -1) {
		ret = errno;
		goto out;
	}
	if (written != sizeof(struct hash_file_header)) {
		ret = EIO;
		goto out;
	}

out:
	free(disk);
	return ret;
}

int write_file_info(int fd, struct filerec *file)
{
	int written, name_len;
	struct file_info finfo = { 0, };
	char *n;

	finfo.ino = cpu_to_le64(file->inum);
	finfo.file_size = 0ULL; /* We don't store this yet */
	finfo.num_blocks = cpu_to_le64(file->num_blocks);
	finfo.subvolid = cpu_to_le64(file->subvolid);

	name_len = strlen(file->filename);
	finfo.name_len = cpu_to_le16(name_len);
	finfo.rec_len = cpu_to_le16(name_len + sizeof(struct file_info));

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

int write_one_hash(int fd, uint64_t loff, uint32_t flags,
			  unsigned char *digest)
{
	int written;
	struct block_hash disk_block = { 0, };

	disk_block.loff = cpu_to_le64(loff);
	disk_block.flags = cpu_to_le32(flags);
	BUILD_BUG_ON(DISK_DIGEST_LEN < DIGEST_LEN_MAX);
	memcpy(&disk_block.digest, digest, DISK_DIGEST_LEN);

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
	struct filerec *file;
	struct file_block *block;
	uint64_t tot_files, tot_hashes;

	fd = open(filename, O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (fd == -1)
		return errno;

	/* Write the header first with zero files */
	ret = write_header(fd, 0, 0, block_size);
	if (ret)
		goto out;

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
			ret = write_one_hash(fd, block->b_loff, block->b_flags,
					     block->b_parent->dl_hash);
			if (ret)
				goto out;
		}
	}

	/* When we're done, rewrite the header */
	ret = write_header(fd, tot_files, tot_hashes, block_size);

out:
	close(fd);
	return ret;
}

static int read_file(int fd, struct file_info *f, char *fname)
{
	int ret, name_len;

	ret = read(fd, f, sizeof(struct file_info));
	if (ret == -1)
		return errno;
	if (ret < sizeof(struct file_info)) {
		/* We reached EOF when we expected to have more files
		 * to read in */
		return EIO;
	}
	name_len = le16_to_cpu(f->name_len);

	ret = read(fd, fname, name_len);
	if (ret == -1)
		return errno;
	if (ret != name_len)
		return EIO;

	fname[name_len] = '\0';

	return 0;
}

static int read_hash(int fd, struct block_hash *b)
{
	int ret;

	ret = read(fd, b, sizeof(struct block_hash));
	if (ret == -1)
		return errno;
	if (ret != sizeof(struct block_hash))
		return EIO;

	return 0;
}

static int read_one_file(int fd, struct hash_tree *tree,
				struct hash_tree *scan_tree)
{
	int ret;
	uint32_t i;
	uint64_t num_blocks;
	struct file_info finfo = {0, };
	struct block_hash bhash;
	struct filerec *file;
	char fname[PATH_MAX+1];
	struct dupe_blocks_list *tmp;

	ret = read_file(fd, &finfo, fname);
	if (ret)
		return ret;

	num_blocks = le64_to_cpu(finfo.num_blocks);

	dprintf("Load %"PRIu64" hashes for \"%s\"\n", num_blocks, fname);

	file = filerec_new(fname, le64_to_cpu(finfo.ino),
			   le64_to_cpu(finfo.subvolid));
	if (file == NULL)
		return ENOMEM;

	for (i = 0; i < num_blocks; i++) {
		ret = read_hash(fd, &bhash);
		if (ret)
			return ret;

/* Filter the data with scan_tree
 * If we made a first pass, scan_tree will store all "possibly dups" hashes.
 * For each read hash, we will search for it in the tree, and only store it
 * if needed.
 * If scan_tree is NULL, we do not want to filter anyway, so bypass the search
 */
		if (scan_tree) {
			tmp = find_block_list(scan_tree,
				(unsigned char *)bhash.digest);
			if (tmp == NULL)
				continue;
		}

		ret = insert_hashed_block(tree, (unsigned char *)bhash.digest,
					  file, le64_to_cpu(bhash.loff),
					  le32_to_cpu(bhash.flags));
		if (ret)
			return ENOMEM;
	}

	return 0;
}

static int read_header(int fd, struct hash_file_header *h)
{
	int ret;

	ret = read(fd, h, sizeof(*h));
	if (ret == -1)
		return errno;
	if (ret != sizeof(struct hash_file_header))
		return EIO;

	debug_print_header(h);

	return 0;
}

int read_hash_tree(char *filename, struct hash_tree *tree,
		   unsigned int *block_size, struct hash_file_header *ret_hdr,
		   int ignore_hash_type, struct hash_tree *scan_tree)
{
	int ret, fd;
	uint32_t i;
	uint64_t num_files;
	struct hash_file_header h;

	memset(&h, 0, sizeof(struct hash_file_header));

	fd = open(filename, O_RDONLY);
	if (fd == -1)
		return errno;

	ret = read_header(fd, &h);
	if (ret)
		return ret;

	if (memcmp(h.magic, HASH_FILE_MAGIC, 8)) {
		ret = FILE_MAGIC_ERROR;
		goto out;
	}
	if (le64_to_cpu(h.major) > HASH_FILE_MAJOR) {
		ret = FILE_VERSION_ERROR;
		goto out;
	}

	if (!ignore_hash_type) {
		uint64_t minor = le64_to_cpu(h.minor);
		/*
		 * v1.0 hash files were SHA256 but wrote out hash_type
		 * as nulls
		 */
		if (minor == 0 && memcmp(hash_type_v1_0, h.hash_type, 8)) {
			ret = FILE_HASH_TYPE_ERROR;
			memcpy(unknown_hash_type, hash_type_v1_0, 8);
			goto out;
		} else  if (minor > 0 && memcmp(h.hash_type, hash_type, 8)) {
			ret = FILE_HASH_TYPE_ERROR;
			memcpy(unknown_hash_type, h.hash_type, 8);
			goto out;
		}
	}

	*block_size = le32_to_cpu(h.block_size);
	num_files = le64_to_cpu(h.num_files);

	dprintf("Load %"PRIu64" files from \"%s\"\n",
		num_files, filename);

	for (i = 0; i < num_files; i++) {
		ret = read_one_file(fd, tree, scan_tree);
		if (ret)
			break;
	}
out:
	if (ret == 0 && ret_hdr)
		memcpy(ret_hdr, &h, sizeof(struct hash_file_header));
	return ret;
}
