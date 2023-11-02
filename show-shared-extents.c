/*
 * show-shared-extents.c
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
 *
 */

#include <sys/stat.h>
#include <stdio.h>

#include "filerec.h"

#ifdef	TEST_FIEMAP_ITER
#define	FLAG_STR_LEN	4096
static char flagstr[FLAG_STR_LEN];
/* This function is not thread-safe */
static char *fiemap_flags_str(unsigned long long flags)
{
	int size = FLAG_STR_LEN;
	int written = 0;
	char *str = flagstr;

	*str = '\0';

	if (flags) {
		written = snprintf(str, size, "(");
		str += written;
		size -= written;
	}

	if (flags & FIEMAP_EXTENT_LAST) {
		written = snprintf(str, size, "last ");
		str += written;
		size -= written;
	}

	if (flags & FIEMAP_EXTENT_UNKNOWN) {
		written = snprintf(str, size, "unknown ");
		str += written;
		size -= written;
	}
	if (flags & FIEMAP_EXTENT_DELALLOC) {
		written = snprintf(str, size, "delalloc ");
		str += written;
		size -= written;
	}
	if (flags & FIEMAP_EXTENT_ENCODED) {
		written = snprintf(str, size, "encoded ");
		str += written;
		size -= written;
	}
	if (flags & FIEMAP_EXTENT_DATA_ENCRYPTED) {
		written = snprintf(str, size, "data_encrypted ");
		str += written;
		size -= written;
	}
	if (flags & FIEMAP_EXTENT_NOT_ALIGNED) {
		written = snprintf(str, size, "not_aligned ");
		str += written;
		size -= written;
	}
	if (flags & FIEMAP_EXTENT_DATA_INLINE) {
		written = snprintf(str, size, "data_inline ");
		str += written;
		size -= written;
	}
	if (flags & FIEMAP_EXTENT_DATA_TAIL) {
		written = snprintf(str, size, "data_tail ");
		str += written;
		size -= written;
	}
	if (flags & FIEMAP_EXTENT_UNWRITTEN) {
		written = snprintf(str, size, "unwritten ");
		str += written;
		size -= written;
	}
	if (flags & FIEMAP_EXTENT_MERGED) {
		written = snprintf(str, size, "merged ");
		str += written;
		size -= written;
	}
	if (flags & FIEMAP_EXTENT_SHARED) {
		written = snprintf(str, size, "shared ");
		str += written;
		size -= written;
	}

	if (flags)
		snprintf(str, size, ")");

	return flagstr;
}

static int test_iter(struct filerec *file)
{
	int ret, bs = 128*1024;
	struct fiemap_ctxt *fc = alloc_fiemap_ctxt();
	unsigned int flags;
	uint64_t loff, poff, len;

	debug = 1;	/* Want prints from filerec_count_shared */

	if (!fc)
		return ENOMEM;

	flags = 0;
	loff = len = 0;
	while (!(flags & FIEMAP_EXTENT_LAST) && loff + len < file->size) {
		ret = fiemap_iter_next_extent(fc, file->fd, &poff, &loff, &len,
					      &flags);
		if (ret)
			return ret;

		printf("(test_iter) %s: poff: %"PRIu64" loff: %"PRIu64" len: %"
		       PRIu64" flags: %s\n",
		       file->filename, poff, loff, len, fiemap_flags_str(flags));
	}

out:
	free(fc);
	return ret;
}
#endif	/* TEST_FIEMAP_ITER */

static int get_size(struct filerec *file)
{
	int ret;
	struct stat st;

	ret = lstat(file->filename, &st);
	if (ret == -1)
		return errno;

	file->size = st.st_size;
	return 0;
}

int main(int argc, char **argv)
{
	int ret, i;
	struct filerec *file;
	uint64_t shared;

	init_filerec();

	if (argc < 2) {
		printf("Usage: show_shared_extents filename1 filename2 ...\n");
		return 1;
	}

	for (i = 1; i < argc; i++) {
		file = filerec_new(argv[i], 500 + i, 1, 0, 0);
		if (!file) {
			fprintf(stderr, "filerec_new(): malloc error\n");
			return 1;
		}

		ret = filerec_open(file);
		if (ret)
			goto out;

		ret = get_size(file);
		if (ret)
			goto out;

#ifdef	TEST_FIEMAP_ITER
		test_iter(file);
#else

		shared = 0;
		ret = filerec_count_shared(file, 0, file->size, &shared);
		filerec_close(file);
		if (ret) {
			fprintf(stderr, "fiemap error %d: %s\n", ret, strerror(ret));
			goto out;
		}

		printf("%s: %"PRIu64" shared bytes\n", file->filename, shared);
#endif
		filerec_free(file);
		file = NULL;
	}

out:
	filerec_free(file);
	return ret;
}
