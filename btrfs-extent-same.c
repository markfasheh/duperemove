/*
 * btrfs-extent-same.c
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include "ioctl.h"

unsigned int blocksize;

static void usage(const char *prog)
{
	printf("Usage: %s len file1 loff1 file2 loff2\n", prog);
}

int main(int argc, char **argv)
{
	int ret, src_fd, i, numfiles;
	char *srcf, *destf;
	struct file_dedupe_range *same;
	struct file_dedupe_range_info *info;
	unsigned long long bytes = 0ULL;

	if (argc < 6 || (argc % 2)) {
		usage(argv[0]);
		return 1;
	}

	numfiles = (argc / 2) - 2;

	printf("Deduping %d total files\n", numfiles + 1);

	same = calloc(1,
		      sizeof(struct file_dedupe_range) +
		      sizeof(struct file_dedupe_range_info) * numfiles);
	if (!same)
		return -ENOMEM;

	srcf = argv[2];
	same->src_length = atoll(argv[1]);
	same->src_offset = atoll(argv[3]);
	same->dest_count = numfiles;

	ret = open(srcf, O_RDONLY);
	if (ret < 0) {
		ret = errno;
		fprintf(stderr, "Could not open file %s: (%d) %s\n", srcf, ret,
			strerror(ret));
		return -ret;
	}
	src_fd = ret;

	printf("(%llu, %llu): %s\n", (unsigned long long)same->src_offset,
	       (unsigned long long)same->src_length, srcf);

	for (i = 0; i < same->dest_count; i++) {
		destf = argv[4 + (i * 2)];

		ret = open(destf, O_WRONLY);
		if (ret < 0) {
			ret = errno;
			fprintf(stderr, "Could not open file %s: (%d) %s\n",
				destf, ret, strerror(ret));
			return -ret;
		}

		same->info[i].dest_fd = ret;
		same->info[i].dest_offset = atoll(argv[5 + (i * 2)]);
		printf("(%llu, %llu): %s\n",
		       (unsigned long long)same->info[i].dest_offset,
		       (unsigned long long)same->src_length, destf);

	}

	ret = ioctl(src_fd, FIDEDUPERANGE, same);
	if (ret < 0) {
		ret = errno;
		fprintf(stderr, "fideduprange returned error: (%d) %s\n", ret,
			strerror(ret));
		return -ret;
	}

	printf("%u files asked to be deduped\n", same->dest_count);

	for (i = 0; i < same->dest_count; i++) {
		info = &same->info[i];

		printf("i: %d, status: %d, bytes_deduped: %llu\n", i,
		       info->status, (unsigned long long)info->bytes_deduped);

		bytes += info->bytes_deduped;
	}

	printf("%llu total bytes deduped in this operation\n", bytes);

	return ret;
}
