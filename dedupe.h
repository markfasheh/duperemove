/*
 * dedupe.h
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

#ifndef	__DEDUPE_H__
#define	__DEDUPE_H__

#include "list.h"
#include "btrfs-ioctl.h"

#define MAX_DEDUPES_PER_IOCTL	120

struct dedupe_ctxt {

	/*
	 * Starting len/file off saved for the callers convenience -
	 * the ones below can change during dedupe operations.
	 */
	uint64_t	orig_len;
	uint64_t	orig_file_off;

	uint64_t	len;
	struct filerec	*ioctl_file;
	uint64_t	ioctl_file_off;

	/* Next two are used for sanity checking */
	unsigned int		max_queable;
	unsigned int		num_queued;

	unsigned int		same_size;

	/*
	 * Keep blocksize 64 bits wide here so we can use it for
	 * aligning the (64 bits wide) context length.
	 */
	uint64_t		fs_blocksize;

	/*
	 * request tracking.
	 *	queued: request is awaiting dedupe
	 *	in_progress: currently undergoing dedupe operations
	 *	completed: results of dedupe for this request are available
	 */
	struct list_head	queued;
	struct list_head	in_progress;
	struct list_head	completed;

	struct btrfs_ioctl_same_args	*same;
};

struct dedupe_ctxt *new_dedupe_ctxt(unsigned int max_extents, uint64_t loff,
				    uint64_t elen, struct filerec *ioctl_file);
void free_dedupe_ctxt(struct dedupe_ctxt *ctxt);

/*
 * add_extent_to_dedupe returns:
 *  < 0: error
 * == 0: no more extents after this one
 *  > 0: ok, can accept more extents
 */
int add_extent_to_dedupe(struct dedupe_ctxt *ctxt, uint64_t loff,
			 struct filerec *file);
int dedupe_extents(struct dedupe_ctxt *ctxt);
int pop_one_dedupe_result(struct dedupe_ctxt *ctxt, int *status,
			  uint64_t *off, uint64_t *bytes_deduped,
			  struct filerec **file);

#endif	/* __DEDUPE_H__ */
