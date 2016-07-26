/*
 * btrfs-util.h
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

#ifndef	__BTRFS_UTIL__
#define	__BTRFS_UTIL__

int lookup_btrfs_subvolid(int fd, uint64_t *rootid);
/*
 * Figure out if we're btrfs. If we are, get the fsid. Otherwise
 * put 0 in *ret_fsid.
 *
 * Returns nonzero on error.
 */
int check_btrfs_get_fsid(char *name, struct stat *st, uint64_t *ret_fsid);

#endif	/* __BTRFS_UTIL__ */
