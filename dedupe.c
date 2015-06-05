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
#include <sys/vfs.h>

#include <errno.h>

#include "kernel.h"
#include "list.h"
#include "filerec.h"
#include "dedupe.h"
#include "debug.h"

static int must_align_len = 0;

struct dedupe_req {
	struct filerec		*req_file;
	struct list_head	req_list; /* see comment in dedupe.h */

	uint64_t		req_loff;
	uint64_t		req_total; /* total bytes processed by kernel */
	int			req_status;
	int			req_idx; /* index into same->info */
};

static struct dedupe_req *new_dedupe_req(struct filerec *file, uint64_t loff)
{
	struct dedupe_req *req = calloc(1, sizeof(*req));

	if (req) {
		INIT_LIST_HEAD(&req->req_list);
		req->req_file = file;
		req->req_loff = loff;
	}
	return req;
}

static void free_dedupe_req(struct dedupe_req *req)
{
	if (req) {
		if (!list_empty(&req->req_list)) {
			struct filerec *file = req->req_file;

			fprintf(stderr,
				"%s: freeing request with nonempty list\n",
				file ? file->filename : "(null)");
			list_del(&req->req_list);
		}
		free(req);
	}
}

static struct dedupe_req *same_idx_to_request(struct dedupe_ctxt *ctxt, int idx)
{
	int i;
	struct dedupe_req *req;
	struct list_head *lists[3] = { &ctxt->queued,
				      &ctxt->in_progress,
				      &ctxt->completed, };

	for (i = 0; i < 3; i++) {
		list_for_each_entry(req, lists[i], req_list) {
			if (req->req_idx == idx)
				return req;
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
	struct dedupe_req *req;

	dprintf(_PRE"btrfs same info: ioctl_file: \"%s\"\n",
		file ? file->filename : "(null)");
	dprintf(_PRE"logical_offset: %llu, length: %llu, dest_count: %u\n",
		(unsigned long long)same->logical_offset,
		(unsigned long long)same->length, same->dest_count);

	for (i = 0; i < same->dest_count; i++) {
		info = &same->info[i];
		req = same_idx_to_request(ctxt, i);
		file = req->req_file;
		dprintf(_PRE"info[%d]: name: \"%s\", fd: %llu, logical_offset: "
			"%llu, bytes_deduped: %llu, status: %d\n",
			i, file ? file->filename : "(null)", (long long)info->fd,
			(unsigned long long)info->logical_offset,
			(unsigned long long)info->bytes_deduped, info->status);
	}
}

static void clear_lists(struct dedupe_ctxt *ctxt)
{
	int i;
	struct list_head *lists[3] = { &ctxt->queued,
				      &ctxt->in_progress,
				      &ctxt->completed, };
	struct dedupe_req *req, *tmp;

	for (i = 0; i < 3; i++) {
		list_for_each_entry_safe(req, tmp, lists[i], req_list) {
			list_del_init(&req->req_list);
			free_dedupe_req(req);
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

static unsigned int get_fs_blocksize(struct filerec *file)
{
	int ret;
	struct statfs fs;

	ret = fstatfs(file->fd, &fs);
	if (ret)
		return 0;
	return fs.f_bsize;
}

struct dedupe_ctxt *new_dedupe_ctxt(unsigned int max_extents, uint64_t loff,
				    uint64_t elen, struct filerec *ioctl_file)
{
	struct dedupe_ctxt *ctxt = calloc(1, sizeof(*ctxt));
	struct btrfs_ioctl_same_args *same;
	unsigned int same_size;
	unsigned int max_dest_files;

	if (ctxt == NULL)
		return NULL;

	if (max_extents > MAX_DEDUPES_PER_IOCTL)
		max_extents = MAX_DEDUPES_PER_IOCTL;

	max_dest_files = max_extents - 1;

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

	ctxt->fs_blocksize = get_fs_blocksize(ioctl_file);
	if (!ctxt->fs_blocksize) {
		free(same);
		free(ctxt);
		return NULL;
	}

	return ctxt;
}

int add_extent_to_dedupe(struct dedupe_ctxt *ctxt, uint64_t loff,
			 struct filerec *file)
{
	struct dedupe_req *req = new_dedupe_req(file, loff);

	abort_on(ctxt->num_queued >= ctxt->max_queable);

	if (req == NULL)
		return -1;

	list_add_tail(&req->req_list, &ctxt->queued);
	ctxt->num_queued++;

	return ctxt->max_queable - ctxt->num_queued;
}

static void add_dedupe_request(struct dedupe_ctxt *ctxt,
			       struct btrfs_ioctl_same_args *same,
			       struct dedupe_req *req)
{
	int same_idx = same->dest_count;
	struct btrfs_ioctl_same_extent_info *info;
	struct filerec *file = req->req_file;

	abort_on(same->dest_count >= ctxt->max_queable);

	req->req_idx = same_idx;
	info = &same->info[same_idx];
	info->fd = file->fd;
	info->logical_offset = req->req_loff;
	info->bytes_deduped = 0;
	same->dest_count++;

	vprintf("add ioctl request %s, off: %llu, dest: %d\n", file->filename,
		(unsigned long long)req->req_loff, same->dest_count);
}

static void set_aligned_same_length(struct dedupe_ctxt *ctxt,
				    struct btrfs_ioctl_same_args *same)
{
	same->length = ctxt->len;
	if (must_align_len && ctxt->len > ctxt->fs_blocksize)
		same->length = ctxt->len & ~(ctxt->fs_blocksize - 1);
}

static void populate_dedupe_request(struct dedupe_ctxt *ctxt,
				    struct btrfs_ioctl_same_args *same)
{
	struct dedupe_req *req, *tmp;

	memset(same, 0, ctxt->same_size);

	set_aligned_same_length(ctxt, same);
	same->logical_offset = ctxt->ioctl_file_off;

	list_for_each_entry_safe(req, tmp, &ctxt->queued, req_list) {
		add_dedupe_request(ctxt, same, req);

		list_move_tail(&req->req_list, &ctxt->in_progress);
		ctxt->num_queued--;
	}
}

/* Returns 1 when there are no more dedupes to process. */
static void process_dedupes(struct dedupe_ctxt *ctxt,
			    struct btrfs_ioctl_same_args *same)
{
	int same_idx;
	uint64_t max_deduped = 0;
	struct btrfs_ioctl_same_extent_info *info;
	struct dedupe_req *req, *tmp;

	list_for_each_entry_safe(req, tmp, &ctxt->in_progress, req_list) {
		same_idx = req->req_idx;
		info = &same->info[same_idx];

		if (info->bytes_deduped > max_deduped)
			max_deduped = info->bytes_deduped;

		req->req_loff += info->bytes_deduped;
		req->req_total += info->bytes_deduped;

		if (info->status || req->req_total >= ctxt->orig_len) {
			/*
			 * Only bother taking the final status (the
			 * rest will be 0)
			 */
			req->req_status = info->status;
			list_move_tail(&req->req_list, &ctxt->completed);
		} else {
			/*
			 * put us back on the queued list for another
			 * go around
			 */
			list_move_tail(&req->req_list, &ctxt->queued);
			ctxt->num_queued++;
		}
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

retry:
		ret = btrfs_extent_same(ctxt->ioctl_file->fd, ctxt->same);
		if (ret)
			break;

		if (debug)
			print_btrfs_same_info(ctxt);

		if (ctxt->same->info[0].status == -EINVAL && !must_align_len) {
			must_align_len = 1;
			set_aligned_same_length(ctxt, ctxt->same);
			goto retry;
		}

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
	struct dedupe_req *req;

	/*
	 * We should not be called if dedupe_extents wasn't called or if
	 * we already passed back all the results..
	 */
	abort_on(list_empty(&ctxt->completed));

	req = list_entry(ctxt->completed.next, struct dedupe_req, req_list);
	list_del_init(&req->req_list);

	*status = req->req_status;
	*off = req->req_loff - req->req_total;
	*bytes_deduped = req->req_total;
	*file = req->req_file;

	free_dedupe_req(req);

	return !!list_empty(&ctxt->completed);
}
