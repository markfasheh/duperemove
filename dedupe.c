/*
 * dedupe.c
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
 */

#include <stdlib.h>

#include "dedupe.h"

void free_dedupe_ctxt(struct dedupe_ctxt *ctxt)
{
	if (ctxt) {
		if (ctxt->filerec_index)
			free(ctxt->filerec_index);
		if (ctxt->same)
			free(ctxt->same);
		free(ctxt);
	}
}

struct dedupe_ctxt *new_dedupe_ctxt(unsigned int max_extents, uint64_t loff,
				    uint64_t elen,  int fd,
				    unsigned int filerec_index)
{
	struct dedupe_ctxt *ctxt = calloc(1, sizeof(*ctxt));
	struct btrfs_ioctl_same_args *same;
	unsigned int same_size;

	if (ctxt == NULL)
		return NULL;

	ctxt->filerec_index = calloc(max_extents - 1, sizeof(unsigned int));
	if (ctxt->filerec_index == NULL) {
		free(ctxt);
		return NULL;
	}

	same_size = sizeof(*same) +
		(max_extents - 1) * sizeof(struct btrfs_ioctl_same_extent_info);
	same = calloc(1, same_size);
	if (same == NULL) {
		free(ctxt->filerec_index);
		free(ctxt);
		return NULL;
	}

	ctxt->same = same;

	ctxt->max_extents = max_extents;
	ctxt->len = ctxt->same->length = elen;
	ctxt->ioctl_fd = fd;
	ctxt->ioctl_fd_index = filerec_index;
	ctxt->ioctl_fd_off = same->logical_offset = loff;

	return ctxt;
}

void add_extent_to_dedupe(struct dedupe_ctxt *ctxt, uint64_t loff, uint64_t len,
			  int fd, unsigned int filerec_index)
{
	int i = ctxt->same->dest_count;
	struct btrfs_ioctl_same_args *same = ctxt->same;

	if (ctxt->same->dest_count >= ctxt->max_extents)
		abort();

	same->info[i].logical_offset = loff;
	same->info[i].fd = fd;
	ctxt->filerec_index[i] = filerec_index;
	same->dest_count++;
}

int dedupe_extents(struct dedupe_ctxt *ctxt)
{
	return btrfs_extent_same(ctxt->ioctl_fd, ctxt->same);
}

void get_dedupe_result(struct dedupe_ctxt *ctxt, int idx, int *status,
		       uint64_t *off, uint64_t *bytes_deduped,
		       unsigned int *filerec_index)
{
	struct btrfs_ioctl_same_extent_info *info = &ctxt->same->info[idx];

	*status = info->status;
	*off = info->logical_offset;
	*bytes_deduped = info->bytes_deduped;
	*filerec_index = ctxt->filerec_index[idx];
}
