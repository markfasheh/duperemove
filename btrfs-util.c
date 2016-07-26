/*
 * btrfs-util.c
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
 * Some parts of this taken from btrfs-progs, which is also GPLv2
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/statfs.h>
#include <sys/ioctl.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <linux/magic.h>
#include <linux/btrfs.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "btrfs-util.h"
#include "debug.h"

/* For some reason linux/btrfs.h doesn't define this. */
#define	BTRFS_FIRST_FREE_OBJECTID	256ULL

/*
 * For a given:
 * - file or directory return the containing tree root id
 * - subvolume return its own tree id
 * - BTRFS_EMPTY_SUBVOL_DIR_OBJECTID (directory with ino == 2) the result is
 *   undefined and function returns -1
 */
int lookup_btrfs_subvolid(int fd, uint64_t *subvolid)
{
	int ret;
	struct btrfs_ioctl_ino_lookup_args args;

	memset(&args, 0, sizeof(args));
	args.objectid = BTRFS_FIRST_FREE_OBJECTID;

	ret = ioctl(fd, BTRFS_IOC_INO_LOOKUP, &args);
	if (ret)
		return errno;

	*subvolid = args.treeid;

	return 0;
}

static uint64_t get_btrfs_fsid(fsid_t in_statfs_fsid, uint64_t subvolid,
			       fsid_t *out_fsid)
{
	int *old_fsid = (int *)&in_statfs_fsid;
	int tmp[2];
	int *fsid = tmp;
	uint64_t ret;

	if (out_fsid)
		fsid = (int *)out_fsid;

	/*
	 * fsid_t is represented as array of 2 ints.
	 *
	 * For fsid, btrfs xors different portions of the fs uuid into
	 * each component of the fsid array. It then masks in the
	 * subvolume root objectid.
	 *
	 * We can reverse the masking to get a unique identifier for
	 * this filesystem.
	 */

	fsid[0] = old_fsid[0] ^ (subvolid >> 32);
	fsid[1] = old_fsid[1] ^ subvolid;

	ret = (uint64_t)fsid[0] & ((1ULL << 32) - 1);
	ret |=(uint64_t)fsid[1] << 32;
	return ret;
}

/*
 * Figure out if we're btrfs. If we are, get the fsid. Otherwise
 * return 0 in *ret_fsid.
 */
int check_btrfs_get_fsid(char *name, struct stat *st, uint64_t *ret_fsid)
{
	struct statfs fs;
	int ret, fd;
	uint64_t subvol;

	*ret_fsid = 0;
	ret = statfs(name, &fs);
	if (ret) {
		ret = errno;
		goto out;
	}

	if (fs.f_type != BTRFS_SUPER_MAGIC)
		return 0;

	fd = open(name, O_RDONLY);
	if (fd == -1) {
		ret = errno;
		goto out;
	}

	ret = lookup_btrfs_subvolid(fd, &subvol);
	if (ret)
		ret = errno;

	*ret_fsid = get_btrfs_fsid(fs.f_fsid, subvol, NULL);

	close(fd);
out:
	return ret;
}

#ifdef	BTRFS_UTIL_TEST
static int get_fsid(int fd, fsid_t *ret_fsid)
{
	int ret;
	struct statfs fs;
	fsid_t fsid;
	uint64_t subvolid;
	int *f;

	ret = fstatfs(fd, &fs);
	if (ret)
		return errno;

	if (fs.f_type == BTRFS_SUPER_MAGIC) {
		uint64_t id;

		ret = lookup_btrfs_subvolid(fd, &subvolid);
		if (ret)
			return ret;

		id = get_btrfs_fsid(fs.f_fsid, subvolid, &fsid);

		f = (int *)&fs.f_fsid;
//		printf("btrfs fsid: %x.%x (%"PRIx64", subvol: %llu\n",
//		       f[1], f[0], id, (unsigned long long)subvolid);
	} else {
		fsid = fs.f_fsid;
	}
	*ret_fsid = fsid;
	return 0;
}

int main(int argc, char **argv)
{
	int i, ret, fd;
	char *filename;
	fsid_t fsid;
	int *f;

	if (argc < 2) {
		printf("Missing arguments\n");
		return 1;
	}

	for (i = 1; i < argc; i++) {
		filename = argv[i];

		fd = open(filename, O_RDONLY);
		if (fd == -1) {
			perror("opening file");
			continue;
		}

		ret = get_fsid(fd, &fsid);
		if (ret) {
			fprintf(stderr, "ERROR: %d\n", ret);
			return ret;
		}
		f = (int *)&fsid;
		printf("%s: fsid: %x.%x\n", filename, f[1], f[0]);

		close(fd);
	}

	return 0;
}
#endif	/* BTRFS_UTIL_TEST */
