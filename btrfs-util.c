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
#ifndef	NO_BTRFS_HEADER
#include <linux/btrfs.h>
#endif
#include <sys/ioctl.h>

#include "btrfs-util.h"
#include "debug.h"

#ifdef	NO_BTRFS_HEADER
#ifndef	__u64
#define	__u64	uint64_t
#endif
#define BTRFS_IOCTL_MAGIC 0x94

#define BTRFS_IOC_INO_LOOKUP _IOWR(BTRFS_IOCTL_MAGIC, 18, \
				   struct btrfs_ioctl_ino_lookup_args)
#define BTRFS_INO_LOOKUP_PATH_MAX 4080
struct btrfs_ioctl_ino_lookup_args {
	__u64 treeid;
	__u64 objectid;
	char name[BTRFS_INO_LOOKUP_PATH_MAX];
};
#endif

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

int check_file_btrfs(int fd, int *btrfs)
{
	int ret;
	struct statfs fs;

	*btrfs = 0;

	ret = fstatfs(fd, &fs);
	if (ret)
		return errno;

	if (fs.f_type == BTRFS_SUPER_MAGIC)
		*btrfs = 1;

	return ret;
}
