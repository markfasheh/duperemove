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
#include <uuid/uuid.h>

#include "btrfs-util.h"
#include "debug.h"
#include "util.h"

/* For some reason linux/btrfs.h doesn't define this. */
#define	BTRFS_FIRST_FREE_OBJECTID	256ULL

/*
 * For a given:
 * - file or directory return the containing tree root id
 * - subvolume return its own tree id
 * - BTRFS_EMPTY_SUBVOL_DIR_OBJECTID (directory with ino == 2) the result is
 *   undefined and function returns -1
 */
int lookup_btrfs_subvol(int fd, uint64_t *subvol)
{
	int ret;
	struct btrfs_ioctl_ino_lookup_args args;

	memset(&args, 0, sizeof(args));
	args.objectid = BTRFS_FIRST_FREE_OBJECTID;

	ret = ioctl(fd, BTRFS_IOC_INO_LOOKUP, &args);
	if (ret)
		return errno;

	*subvol = args.treeid;

	return 0;
}

int is_btrfs(char *path)
{
	struct statfs fs;
	int ret;

	ret = statfs(path, &fs);
	if (ret)
		return errno;

	return fs.f_type == BTRFS_SUPER_MAGIC;
}

int btrfs_get_fsuuid(int fd, uuid_t *uuid)
{
	int ret;
	struct btrfs_ioctl_fs_info_args args = {0,};

	args.flags = BTRFS_FS_INFO_FLAG_METADATA_UUID;

	ret = ioctl(fd, BTRFS_IOC_FS_INFO, &args);
	if (ret)
		return errno;

	uuid_copy(*uuid, args.metadata_uuid);
	return 0;
}
