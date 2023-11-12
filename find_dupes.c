/*
 * find_dupes.c
 *
 * Implementation of duplicate extent search
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include <inttypes.h>
#include <glib.h>

#include "csum.h"
#include "rbtree.h"
#include "list.h"
#include "filerec.h"
#include "hash-tree.h"
#include "results-tree.h"
#include "dbfile.h"
#include "memstats.h"
#include "debug.h"

#include "find_dupes.h"

/*
 * Extent search status globals. This could be an atomic but GCond
 * requires a mutex so we might as well use it...
 */
static unsigned long long	search_total;
static unsigned long long	search_processed;
static GMutex			progress_mutex;
static GCond			progress_updated;

/* XXX: This is allowed to be called *after* update_extent_search_status() */
static void set_extent_search_status_count(unsigned long long nr_items)
{
	search_total = nr_items;
}

static void print_extent_search_status(unsigned long long processed)
{
	static int last_pos = -1;
	int i, pos;
	int width = 40;
	float progress;

	progress = (float) processed / search_total;
	pos = width * progress;

	/* Only update our status every width% */
	if (pos <= last_pos)
		return;
	last_pos = pos;

	printf("\r[");
	for(i = 0; i < width; i++) {
		if (i < pos)
			printf("#");
		else if (i == pos)
			printf("%%");
		else
			printf(" ");
	}
	printf("]");
}

/*
 * 'err' is impossible in the current code when this is called, but we
 * can keep the handling here in case that changes.
 */
static void clear_extent_search_status(unsigned long long processed,
				       int err)
{
	if (err)
		printf("\nSearch exited (%llu processed) with error %d: "
		       "\"%s\"\n", processed, err, strerror(err));
	else
		printf("\nSearch completed with no errors.             \n");
}

static void update_extent_search_status(unsigned long long processed)
{
	g_mutex_lock(&progress_mutex);
	search_processed += processed;
	g_cond_signal(&progress_updated);
	g_mutex_unlock(&progress_mutex);
}

static void wait_update_extent_search_status()
{
	uint64_t end_time = g_get_monotonic_time () + 1 * G_TIME_SPAN_SECOND;
	unsigned long long tmp, last = 0;

	if (!isatty(STDOUT_FILENO) || verbose || debug)
		return;

	/* Get the bar started */
	print_extent_search_status(0);

	g_mutex_lock(&progress_mutex);
	while (search_processed < search_total) {
		g_cond_wait_until(&progress_updated, &progress_mutex, end_time);
		tmp = search_processed;
		g_mutex_unlock(&progress_mutex);

		if (tmp != last)
			print_extent_search_status(tmp);
		last = tmp;

		g_mutex_lock(&progress_mutex);
	}
	g_mutex_unlock(&progress_mutex);

	print_extent_search_status(search_processed);
	clear_extent_search_status(search_processed, 0);
}

static inline unsigned long block_len(struct file_block *block)
{
	/* Block is not near the end of file */
	if (block->b_loff + blocksize <= block->b_file->size)
		return blocksize;

	/* Block is at the end, or passed the end .. should not happen */
	if (block->b_loff >= block->b_file->size)
		return 0;

	/* We are in the last "blocksize" part of the file */
	return (block->b_file->size - block->b_loff) % blocksize;
}

static void record_match(struct results_tree *res, unsigned char *digest,
			 struct filerec *orig, struct filerec *walk,
			 struct file_block **start, struct file_block **end)
{
	int ret;
	uint64_t soff[2], eoff[2];
	struct filerec *recs[2];
	uint64_t len;

	abort_on(start[0]->b_file != orig);
	abort_on(start[1]->b_file != walk);

	recs[0] = start[0]->b_file;
	recs[1] = start[1]->b_file;

	soff[0] = start[0]->b_loff;
	soff[1] = start[1]->b_loff;

	eoff[0] = block_len(end[0]) + end[0]->b_loff - 1;
	eoff[1] = block_len(end[1]) + end[1]->b_loff - 1;

	len = eoff[0] - soff[0] + 1;

	ret = insert_result(res, digest, recs, soff, eoff);
	if (ret) {
		abort_on(ret != ENOMEM); /* Only error possible here. */
		fprintf(stderr, "Out of memory while processing results\n");
		print_mem_stats();
		exit(ENOMEM);
	}

	dprintf("Duplicated extent of %llu blocks in files:\n%s\t\t%s\n",
		(unsigned long long)len / blocksize, orig->filename,
		walk->filename);

	dprintf("%llu-%llu\t\t%llu-%llu\n",
		(unsigned long long)soff[0] / blocksize,
		(unsigned long long)eoff[0] / blocksize,
		(unsigned long long)soff[1] / blocksize,
		(unsigned long long)eoff[1] / blocksize);
}

struct find_dupes_cmp {
	struct filerec *file1;
	struct filerec *file2;
};
declare_alloc_tracking(find_dupes_cmp);

static inline struct file_block *get_next_block(struct file_block *b)
{
	struct rb_node *node;

	node = rb_next(&b->b_file_next);

	abort_on(!node);

	return rb_entry(node, struct file_block, b_file_next);
}

static inline int end_of_block_list(struct file_block *b)
{
	return !rb_next(&b->b_file_next);
}

/*
 * We search search_len bytes. If search_len == UINT64_MAX
 * then we'll search until end of file.
 */
static int compare_extents(struct filerec *orig_file,
			   struct file_block *orig_file_block,
			   struct filerec *walk_file,
			   struct file_block *walk_file_block,
			   uint64_t search_len,
			   struct results_tree *res)
{
	struct file_block *orig = orig_file_block;
	struct file_block *block = walk_file_block;
	struct file_block *start[2];
	struct file_block *end[2] = { NULL, NULL };
	uint64_t extent_end;
	struct running_checksum *csum;
	unsigned char match_id[DIGEST_LEN] = {0, };
	uint64_t orig_blkno, walk_blkno, match_end;
	bool matchmore = true;

	extent_end = block->b_loff + search_len - 1;

next_match:
	start[0] = orig;
	start[1] = block;
	/*
	 * Fast-forward to a match, if we can find one. This doesn't
	 * run on the first match as callers start the search on
	 * identical blocks. We might also exit without finding any
	 * match start.
	 */
	while (block->b_parent != orig->b_parent && block->b_loff < extent_end) {
		/*
		 * Check that we don't walk off either tree
		 */
		if (end_of_block_list(orig) || end_of_block_list(block))
			return 0;

		orig = get_next_block(orig);
		block = get_next_block(block);
	}
	/*
	 * XXX: There's no need for this, we ought to just generate a
	 * unique identifier for our tree.
	 */
	csum = start_running_checksum();

	while (block->b_parent == orig->b_parent && block->b_loff < extent_end) {
		end[0] = orig;
		end[1] = block;

		add_to_running_checksum(csum, DIGEST_LEN,
					block->b_parent->dl_hash);

		if (end_of_block_list(orig) || end_of_block_list(block)) {
			matchmore = false;
			break;
		}

		orig_blkno = orig->b_loff;
		walk_blkno = block->b_loff;

		orig = get_next_block(orig);
		block = get_next_block(block);

		/*
		 * Check that our next blocks are contiguous wrt the
		 * old ones. If they aren't, then this has to be the
		 * end of our extent.
		 */
		if (orig->b_loff != (orig_blkno + blocksize) ||
		    block->b_loff != (walk_blkno + blocksize)) {
			matchmore = false;
			break;
		}
	}

	finish_running_checksum(csum, match_id);

	/*
	 * No matches - we never even entered the search loop. This
	 * would happen if we were called on two start blocks that do
	 * not have a match.
	 */
	if (!end[0])
		return 0;

	/*
	 * Our options:
	 *
	 * - limit searches and matches to length of original
	 *   extent (what we do now)
	 *
	 * - don't limit search or matches at all (what we have in
         *   walk_dupe_block())
	 */
	match_end = block_len(end[1]) + end[1]->b_loff - 1;
	if (match_end <= extent_end)
		record_match(res, match_id, orig_file, walk_file, start, end);
	else
		return 0;

	if (matchmore) {
		if (end_of_block_list(end[0]) || end_of_block_list(end[1]))
			return 0;

		if (block->b_loff > extent_end)
			return 0;

		orig = get_next_block(end[0]);
		block = get_next_block(end[1]);

		end[0] = end[1] = NULL;

		goto next_match;
	}
	return 0;
}

static int search_extent(struct filerec *file, struct file_extent *extent,
			 struct results_tree *dupe_extents, struct dbhandle *db)
{
	int ret = 0;
	struct file_block *block, *found_block;
	struct filerec *found_file;
	struct dupe_blocks_list *blocklist;
	struct file_extent found_extent;

	block = find_filerec_block(file, extent->loff);
	/* No dupe block so no possible dupe. */
	if (!block)
		return 0;

#if 0
	dprintf("Search file %s loff %"PRIu64" len %"PRIu64" hash ",
		file->filename, extent->loff, extent->len);
	if (debug)
		debug_print_digest_short(stdout, block->b_parent->dl_hash);
	dprintf("\n");
#endif

	blocklist = block->b_parent;

	list_for_each_entry(found_block, &blocklist->dl_list, b_list) {
		if (found_block == block)
			continue;

		found_file = found_block->b_file;
		if (!options.dedupe_same_file && file == found_file)
			continue;

		/*
		 * Find the on-disk extent for found_block and check
		 * that we won't be going over the end of it.
		 */
		ret = dbfile_load_one_file_extent(db, found_file,
						  found_block->b_loff,
						  &found_extent);
		if (ret)
			break;

		/*
		 * TODO: Allow us to solve for a dupe that straddles
		 * two extents.
		 */
		ret = compare_extents(file, block, found_file,
				      found_block, extent->len,
				      dupe_extents);
		if (ret)
			break;
		ret = 0;
	}
	return ret;
}

/*
 * Find any file extents which have not been duped and see if we can
 * match them up inside of any of our already duped extents.
 *
 * We don't yet catch the case where a non duped extent straddles more
 * than one extent.
 */
static void search_file_extents(struct filerec *file, struct results_tree *dupe_extents)
{

	int ret;
	struct dbhandle *db;
	struct file_extent *extents = NULL;
	struct file_extent *extent;
	unsigned int num_extents, i;

	dbfile_lock();
	db = dbfile_open_handle(options.hashfile);
	dbfile_unlock();
	if (!db) {
		fprintf(stderr, "ERROR: Couldn't open db file %s\n",
			options.hashfile == NULL ? "(null)" : options.hashfile);
		return;
	}
	/*
	 * Pick a non-deduped extent from file. The extent info
	 * returned here is what was given to us by fiemap.
	 */
	ret = dbfile_load_nondupe_file_extents(db, file, &extents, &num_extents);
	if (ret)
		goto out;
	if (!num_extents)
		goto out;

	dprintf("search_file_extents: %s (size=%"PRIu64" ret %d num_extents: "
		"%u\n", file->filename, file->size, ret, num_extents);
	for(i = 0; i < num_extents; i++) {
		extent = &extents[i];
		dprintf("search_file_extents:   nondupe extent # %d loff %"
			PRIu64" len %"PRIu64" poff %"PRIu64"\n",
			i, extent->loff, extent->len, extent->poff);
		/*
		 * XXX: Here we should collapse contiguous extents
		 * into one larger one
		 */
	}
	for(i = 0; i < num_extents; i++) {
		extent = &extents[i];

		ret = search_extent(file, extent, dupe_extents, db);
		if (ret)
			goto out;
	}

out:
	update_extent_search_status(1);
	if (extents)
		free(extents);

	dbfile_lock();
	dbfile_close_handle(db);
	dbfile_unlock();
}

struct cmp_ctxt {
	struct filerec *file;
	struct results_tree *dupe_extents;
};

static void find_dupes_thread(struct cmp_ctxt *ctxt, void *priv [[maybe_unused]])
{

	struct results_tree *dupe_extents = ctxt->dupe_extents;
	struct filerec *file = ctxt->file;

	free(ctxt);

	search_file_extents(file, dupe_extents);
}

int find_additional_dedupe(struct results_tree *dupe_extents)
{
	int ret = 0;
	GError *err = NULL;
	GThreadPool *pool = NULL;
	struct filerec *file;

	qprintf("Using %u threads to search within extents for "
		"additional dedupe. This process will take some time, during "
		"which Duperemove can safely be ctrl-c'd.\n", options.cpu_threads);

	pool = g_thread_pool_new((GFunc) find_dupes_thread, NULL,
				 options.cpu_threads, TRUE, &err);
	if (err) {
		fprintf(stderr,
			"Unable to create find file dupes thread pool: %s\n",
			err->message);
		g_error_free(err);
		return ENOMEM;
	}

	set_extent_search_status_count(num_filerecs);

	list_for_each_entry(file, &filerec_list, rec_list) {
		/*
		 * This is an empty file - or maybe an error somewhere ?
		 * Anyway, let's skip it and mark it as "processed"
		 */
		if (file->size == 0) {
			update_extent_search_status(1);
			continue;
		}

		struct cmp_ctxt *ctxt = malloc(sizeof(*ctxt));

		if (!ctxt)
			return ENOMEM;

		ctxt->file = file;
		ctxt->dupe_extents = dupe_extents;

		g_thread_pool_push(pool, ctxt, &err);
		if (err) {
			fprintf(stderr,
				"Error from thread pool: %s\n ",
				err->message);
			g_error_free(err);
			return ENOMEM;
		}

		/* XXX: Need to throttle here? */
	}

	wait_update_extent_search_status();

	g_thread_pool_free(pool, FALSE, TRUE);

	/*
	 * Save memory by freeing each filerec compared tree once all
	 * threads have finished.
	 */
//	free_all_filerec_compared();
	return ret;
}
