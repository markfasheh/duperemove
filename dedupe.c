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
 *
 * Authors: Mark Fasheh <mfasheh@suse.de>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "kernel.h"
#include "list.h"
#include "filerec.h"
#include "dedupe.h"
#include "debug.h"

#define MAX_DEDUPES_PER_IOCTL	120

static struct filerec *
same_idx_to_filerec(struct dedupe_ctxt *ctxt, int idx)
{
	int i;
	struct filerec *file;
	struct list_head *lists[3] = { &ctxt->queued,
				      &ctxt->in_progress,
				      &ctxt->completed, };

	for (i = 0; i < 3; i++) {
		list_for_each_entry(file, lists[i], dedupe_list) {
			if (file->dedupe_idx == idx)
				return file;
		}
	}

	return NULL;
}

#define _PRE	"(dedupe) "
static void print_btrfs_same_info(struct dedupe_ctxt *ctxt)
{
	int i;
	struct filerec *file = ctxt->ioctl_file;
	struct btrfs_ioctl_same_args *same = ctxt->same;
	struct btrfs_ioctl_same_extent_info *info;

	dprintf(_PRE"btrfs same info: ioctl_file: \"%s\"\n",
		file ? file->filename : "(null)");
	dprintf(_PRE"logical_offset: %llu, length: %llu, dest_count: %u\n",
		(unsigned long long)same->logical_offset,
		(unsigned long long)same->length, same->dest_count);

	for (i = 0; i < same->dest_count; i++) {
		info = &same->info[i];
		file = same_idx_to_filerec(ctxt, i);
		dprintf(_PRE"info[%d]: name: \"%s\", fd: %llu, logical_offset: "
			"%llu, bytes_deduped: %llu, status: %d\n",
			i, file ? file->filename : "(null)", (long long)info->fd,
			(unsigned long long)info->logical_offset,
			(unsigned long long)info->bytes_deduped, info->status);
	}
}

static void clear_file_dedupe_info(struct filerec *file)
{
	file->dedupe_total = 0;
	file->dedupe_status = 0;
	file->dedupe_loff = 0;
}

static void clear_lists(struct dedupe_ctxt *ctxt)
{
	int i;
	struct list_head *lists[3] = { &ctxt->queued,
				      &ctxt->in_progress,
				      &ctxt->completed, };
	struct filerec *file, *tmp;

	for (i = 0; i < 3; i++) {
		list_for_each_entry_safe(file, tmp, lists[i], dedupe_list) {
			clear_file_dedupe_info(file);
			list_del_init(&file->dedupe_list);
		}
	}
}

void free_dedupe_ctxt(struct dedupe_ctxt *ctxt)
{
	if (ctxt) {
		clear_lists(ctxt);
		if (ctxt->same)
			free(ctxt->same);
		free(ctxt);
	}
}

struct dedupe_ctxt *new_dedupe_ctxt(unsigned int max_extents, uint64_t loff,
				    uint64_t elen, struct filerec *ioctl_file)
{
	struct dedupe_ctxt *ctxt = calloc(1, sizeof(*ctxt));
	struct btrfs_ioctl_same_args *same;
	unsigned int same_size;
	unsigned int max_dest_files = max_extents - 1;

	if (ctxt == NULL)
		return NULL;

	if (max_extents > MAX_DEDUPES_PER_IOCTL)
		max_extents = MAX_DEDUPES_PER_IOCTL;

	same_size = sizeof(*same) +
		max_dest_files * sizeof(struct btrfs_ioctl_same_extent_info);
	same = calloc(1, same_size);
	if (same == NULL) {
		free(same);
		free(ctxt);
		return NULL;
	}

	ctxt->same = same;
	ctxt->same_size = same_size;

	ctxt->max_queable = max_dest_files;
	ctxt->len = ctxt->orig_len = elen;
	ctxt->ioctl_file = ioctl_file;
	ctxt->ioctl_file_off = ctxt->orig_file_off = loff;
	INIT_LIST_HEAD(&ctxt->queued);
	INIT_LIST_HEAD(&ctxt->in_progress);
	INIT_LIST_HEAD(&ctxt->completed);

	return ctxt;
}

int add_extent_to_dedupe(struct dedupe_ctxt *ctxt, uint64_t loff,
			 struct filerec *file)
{
	if (ctxt->num_queued >= ctxt->max_queable)
		abort();

	clear_file_dedupe_info(file);
	file->dedupe_loff = loff;
	list_add_tail(&file->dedupe_list, &ctxt->queued);

	ctxt->num_queued++;

	return ctxt->max_queable - ctxt->num_queued;
}

static int add_dedupe_request(struct dedupe_ctxt *ctxt,
			       struct btrfs_ioctl_same_args *same,
			       struct filerec *file)
{
	int same_idx = same->dest_count;
	struct btrfs_ioctl_same_extent_info *info;

	if (same->dest_count > ctxt->max_queable)
		abort();

	info = &same->info[same_idx];
	info->fd = file->fd;
	info->logical_offset = file->dedupe_loff;
	info->bytes_deduped = 0;
	same->dest_count++;

	dprintf("add request %s, off: %llu, dest: %d\n", file->filename,
	       (unsigned long long)file->dedupe_loff, same->dest_count);

	return same_idx;
}

static void populate_dedupe_request(struct dedupe_ctxt *ctxt,
				    struct btrfs_ioctl_same_args *same)
{
	struct filerec *file, *tmp;

	memset(same, 0, ctxt->same_size);

	same->length = ctxt->len;
	same->logical_offset = ctxt->ioctl_file_off;

	list_for_each_entry_safe(file, tmp, &ctxt->queued, dedupe_list) {
		file->dedupe_idx = add_dedupe_request(ctxt, same, file);

		list_move_tail(&file->dedupe_list, &ctxt->in_progress);
	}
}

/* Returns 1 when there are no more dedupes to process. */
static void process_dedupes(struct dedupe_ctxt *ctxt,
			    struct btrfs_ioctl_same_args *same)
{
	int same_idx;
	uint64_t max_deduped = 0;
	struct btrfs_ioctl_same_extent_info *info;
	struct filerec *file, *tmp;

	list_for_each_entry_safe(file, tmp, &ctxt->in_progress, dedupe_list) {
		same_idx = file->dedupe_idx;
		info = &same->info[same_idx];

		if (info->bytes_deduped > max_deduped)
			max_deduped = info->bytes_deduped;

		file->dedupe_loff += info->bytes_deduped;
		file->dedupe_total += info->bytes_deduped;

		if (info->status || file->dedupe_total >= ctxt->orig_len)
			goto completed;

		/* put us back on the queued list for another go around */
		list_move_tail(&file->dedupe_list, &ctxt->queued);
		continue;
completed:
		/* Only bother taking the final status (the rest will be 0) */
		file->dedupe_status = info->status;
		list_move_tail(&file->dedupe_list, &ctxt->completed);
	}

	/* Increment our ioctl file pointers */
	ctxt->len -= max_deduped;
	ctxt->ioctl_file_off += max_deduped;
}

int dedupe_extents(struct dedupe_ctxt *ctxt)
{
	int ret = 0;

	while (!list_empty(&ctxt->queued)) {
		/* Convert the queued list into an actual request */
		populate_dedupe_request(ctxt, ctxt->same);

		ret = btrfs_extent_same(ctxt->ioctl_file->fd, ctxt->same);
		if (ret)
			break;

		if (debug)
			print_btrfs_same_info(ctxt);

		process_dedupes(ctxt, ctxt->same);
	}

	return ret;
}

/*
 * Returns 1 when we have no more items.
 */
int pop_one_dedupe_result(struct dedupe_ctxt *ctxt, int *status,
			  uint64_t *off, uint64_t *bytes_deduped,
			  struct filerec **file)
{
	struct filerec *f;

	if (list_empty(&ctxt->completed))
		goto out;

	f = list_entry(ctxt->completed.next, struct filerec, dedupe_list);
	list_del_init(&f->dedupe_list);

	*status = f->dedupe_status;
	*off = f->dedupe_loff - f->dedupe_total;
	*bytes_deduped = f->dedupe_total;
	*file = f;

out:
	return !!list_empty(&ctxt->completed);
}
