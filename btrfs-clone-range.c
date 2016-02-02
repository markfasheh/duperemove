/*
 * btrfs-clone-range.c
 *
 * Copyright (C) 2013 SUSE.  All rights reserved.
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
 * Authors: Mark Fasheh <mfasheh@suse.de>
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>

#define BTRFS_IOCTL_MAGIC 0x94

#define BTRFS_IOC_FILE_CLONE_RANGE _IOW(BTRFS_IOCTL_MAGIC, 13, \
					 struct btrfs_ioctl_clone_range_args)

struct btrfs_ioctl_clone_range_args {
	int64_t src_fd;
	uint64_t src_offset, src_length;
	uint64_t dest_offset;
};

static void usage(const char *prog)
{
	printf("Usage: %s len src-file src-off dest-file dest-off\n", prog);
}

int main(int argc, char **argv)
{
	int ret, src_fd, dest_fd;
	char *srcf, *destf;
	struct btrfs_ioctl_clone_range_args range;

	if (argc != 6) {
		usage(argv[0]);
		return 1;
	}

	srcf = argv[2];
	destf = argv[4];

	ret = open(srcf, O_RDONLY);
	if (ret < 0) {
		ret = errno;
		fprintf(stderr, "Could not open source file %s: (%d) %s\n", srcf, ret,
			strerror(ret));
		return -ret;
	}
	src_fd = ret;

	ret = open(destf, O_WRONLY);
	if (ret < 0) {
		ret = errno;
		fprintf(stderr, "Could not open destination file %s: (%d) %s\n", destf, ret,
			strerror(ret));
		return -ret;
	}
	dest_fd = ret;

	range.src_fd = src_fd;
	range.src_length = atoll(argv[1]);
	range.src_offset = atoll(argv[3]);
	range.dest_offset = atoll(argv[5]);

	ret = ioctl(dest_fd, BTRFS_IOC_FILE_CLONE_RANGE, &range);
	if (ret < 0) {
		ret = errno;
		fprintf(stderr, "btrfs_file_clone_range returned error: (%d) %s\n", ret,
			strerror(ret));
		return -ret;
	}

	return ret;
}
