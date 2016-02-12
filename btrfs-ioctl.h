/*
 * btrfs-ioctl.h
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

#ifndef	__BTRFS_IOCTL_H__
#define	__BTRFS_IOCTL_H__

#include <stdint.h>
#include <stddef.h>
#include <sys/ioctl.h>

#define BTRFS_IOCTL_MAGIC 0x94

#define BTRFS_IOC_FILE_EXTENT_SAME _IOWR(BTRFS_IOCTL_MAGIC, 54, \
					 struct btrfs_ioctl_same_args)

#define BTRFS_SAME_DATA_DIFFERS	1
/* For extent-same ioctl */
struct btrfs_ioctl_same_extent_info {
	int64_t fd;			/* in - destination file */
	uint64_t logical_offset;	/* in - start of extent in destination */
	uint64_t bytes_deduped;		/* out - total # of bytes we
					 * were able to dedupe from
					 * this file */
	/* status of this dedupe operation:
	 * 0 if dedup succeeds
	 * < 0 for error
	 * == BTRFS_SAME_DATA_DIFFERS if data differs
	 */
	int32_t status;			/* out - see above description */
	uint32_t reserved;
};

struct btrfs_ioctl_same_args {
	uint64_t logical_offset;	/* in - start of extent in source */
	uint64_t length;		/* in - length of extent */
	uint16_t dest_count;		/* in - total elements in info array */
	uint16_t reserved1;
	uint32_t reserved2;
	struct btrfs_ioctl_same_extent_info info[0];
};

static inline int btrfs_extent_same(int fd,
				    struct btrfs_ioctl_same_args *same)
{
	return ioctl(fd, BTRFS_IOC_FILE_EXTENT_SAME, same);
}

#endif	/* __BTRFS_IOCTL_H__ */
