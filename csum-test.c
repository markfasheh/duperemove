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
 *
 * Authors: Mark Fasheh <mfasheh@suse.de>
 */

/*
 * Use this for two tests:
 *
 * - hash a file so we can compare the result against a 3rd party tool
 *   using the same hash.
 * - test that one-off and running checksum functions return the same
 *   digest for the same input. For example:
 *	$ dd if=/dev/urandom of=4kfilerand count=1 bs=4096
 *	$ ./csum-test -b 1024 4kfilerand
 *	$ ./csum-test -b 4096 4kfilerand
 *   both runs of csum-test above should show the same digest.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>

#include <stdio.h>

#include "csum.h"


static unsigned int buf_len = 4096;
static unsigned char *buf = NULL;

static unsigned char digest[DIGEST_LEN_MAX] = { 0, };
static char *user_hash = DEFAULT_HASH_STR;
enum {
	HASH_OPTION = CHAR_MAX + 1,
};

static int parse_opts(int argc, char **argv, char **fname)
{
	int c;
	static struct option long_ops[] = {
		{ "hash", 1, 0, HASH_OPTION },
		{ 0, 0, 0, 0}
	};

	if (argc < 2)
		return 1;

	while ((c = getopt_long(argc, argv, "b:", long_ops, NULL))
	       != -1) {
		switch (c) {
		case 'b':
			buf_len = atoi(optarg);
			printf("User provided buffer len: %u\n", buf_len);
			break;
		case HASH_OPTION:
			user_hash = optarg;
			break;
		default:
			return 1;
		}
	}

	*fname = argv[optind];

	return 0;
}

int main(int argc, char **argv)
{
	char *fname = NULL;
	int fd, ret;
	ssize_t len;
	struct stat s;
	struct running_checksum *csum;

	ret = parse_opts(argc, argv, &fname);
	if (ret) {
		fprintf(stderr, "Usage: %s [-b buflen] [--hash=hash_type] filename\n", argv[0]);
		return 1;
	}

	ret = init_csum_module(user_hash);
	if (ret)
		return ret;

	buf = malloc(buf_len);
	if (buf == NULL)
		return ENOMEM;

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

	if (s.st_size <= buf_len) {
		printf("File size is smaller than buffer, using one shot\n");
		len = read(fd, buf, buf_len);
		if (len < 0)
			return errno;
		if (len == 0)
			return 1;
		checksum_block((char *)buf, len, digest);
	} else {
		printf("File size is larger than buffer, using running "
		       "checksum\n");
		csum = start_running_checksum();

		while (1) {
			len = read(fd, buf, buf_len);
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
