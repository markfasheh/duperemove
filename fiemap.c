/*
 * fiemap.c
 *
 * Abstract and add helpers to the fiemap ioctl.
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

#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#include "debug.h"
#include "fiemap.h"
#include "util.h"

/*
 * Invoke an empty fiemap ioctl to fetch the number
 * of extent for this file.
 * Returns 0 on error.
 */
static unsigned int fiemap_count_extents(int fd)
{
	struct fiemap fiemap = {0,};
	int err;

	fiemap.fm_length = ~0ULL;

	err = ioctl(fd, FS_IOC_FIEMAP, &fiemap);
	if (err < 0) {
		perror("fiemap_count_extents");
		return 0;
	}

	return fiemap.fm_mapped_extents;
}

struct fiemap_extent *get_extent(struct fiemap *fiemap, size_t loff,
				 unsigned int *index)
{
	struct fiemap_extent *extent;
	size_t ext_end_off;

	for (unsigned int i = 0; i < fiemap->fm_mapped_extents; i++) {
		extent = &fiemap->fm_extents[i];
		ext_end_off = extent->fe_logical + extent->fe_length;
		if (ext_end_off < loff)
			continue;

		if (index)
			*index = i;

		return extent;
	}
	return NULL;
}

struct fiemap *do_fiemap(int fd)
{
	int err;

	struct fiemap *fiemap = NULL;
	unsigned int count = fiemap_count_extents(fd);

	/*
	 * Our structure must be large enough to fit:
	 * - one struct fiemap = 32 bytes
	 * - $count struct fiemap_extent = count * 56 bytes
	 * - $count struct fiemap_extent* = count * 4 bytes
	 * See https://www.kernel.org/doc/Documentation/filesystems/fiemap.txt
	 */
	fiemap = calloc(1, sizeof(struct fiemap) +
			count * (sizeof(struct fiemap_extent) +
			sizeof(struct fiemap_extent *)));

	fiemap->fm_start = 0;
	fiemap->fm_length = ~0ULL;
	fiemap->fm_extent_count = count;

	err = ioctl(fd, FS_IOC_FIEMAP, fiemap);
	if (err < 0) {
		perror("fiemap");
		return NULL;
	}

	if (fiemap->fm_mapped_extents != count) {
		fprintf(stderr, "fiemap: file changed between fiemap calls\n");
		free(fiemap);
		return NULL;
	}

	return fiemap;
}

int fiemap_count_shared(int fd, size_t start_off, size_t end_off, size_t *shared)
{
	_cleanup_(freep) struct fiemap *fiemap = NULL;
	struct fiemap_extent *extent;

	size_t extent_loff;
	size_t extent_end;

	abort_on(start_off >= end_off);

	fiemap = do_fiemap(fd);
	if (!fiemap)
		return 1;

	*shared = 0;

	for (unsigned int i = 0; i < fiemap->fm_mapped_extents; i++) {
		extent = &fiemap->fm_extents[i];

		extent_end = extent->fe_logical + extent->fe_length;
		extent_loff = extent->fe_logical;

		if (start_off <= extent_end && end_off >= extent_loff) {
			if (!(extent->fe_flags & FIEMAP_EXTENT_DELALLOC)
					&& extent->fe_flags & FIEMAP_EXTENT_SHARED) {
				if (extent_loff < start_off)
					extent_loff = start_off;
				if (end_off < extent_end)
					extent_end = end_off;
				*shared += extent_end - extent_loff;
			}
		}
	}
	return 0;
}
