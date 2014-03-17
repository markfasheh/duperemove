/*
 * csum-test.c
 *
 * Test the checksumming code of duperemove. You can compare the
 * output of this software with that of 'sha256sum'
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
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <stdio.h>

#include "csum.h"


#define BUF_LEN	4096
static unsigned char buf[BUF_LEN];
static unsigned char digest[DIGEST_LEN_MAX] = { 0, };

int main(int argc, char **argv)
{
	char *fname = argv[1];
	int fd, ret;
	size_t len;
	struct stat s;
	struct running_checksum *csum;

	init_hash();

	if (argc != 2) {
		fprintf(stderr, "Usage: %s filename\n", argv[0]);
		return 1;
	}

	fd = open(fname, O_RDONLY);
	if (fd < 0)
		return errno;

	/*
	 * If the test file size is less than BUF_LEN we'll exercise
	 * the one-shot function. Otherwise, do a running checksum.
	 */
	ret = fstat(fd, &s);
	if (ret)
		return errno;

	if (s.st_size == 0)
		return 0;

	if (s.st_size <= BUF_LEN) {
		len = read(fd, buf, BUF_LEN);
		if (len < 0)
			return errno;
		if (len == 0)
			return 1;
		checksum_block((char *)buf, len, digest);
	} else {
		csum = start_running_checksum();

		while (1) {
			len = read(fd, buf, BUF_LEN);
			if (len < 0)
				return errno;
			if (len) {
				add_to_running_checksum(csum, len, buf);
			} else
				break; /* EOF */
		}

		finish_running_checksum(csum, digest);
	}

	debug_print_digest(stdout, digest);
	printf("  %s\n", fname);

	return 0;
}
