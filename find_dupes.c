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

#include <inttypes.h>
#include <glib.h>

#include "csum.h"
#include "rbtree.h"
#include "list.h"
#include "filerec.h"
#include "hash-tree.h"
#include "results-tree.h"
#include "memstats.h"
#include "debug.h"

#include "find_dupes.h"

extern int block_dedupe;
extern int dedupe_same_file;
extern unsigned int cpu_threads;

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

	if (!stdout_is_tty || verbose || debug)
		return;

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
	fflush(stdout);
}

/*
 * 'err' is impossible in the current code when this is called, but we
 * can keep the handling here in case that changes.
 */
static void clear_extent_search_status(unsigned long long processed,
				       int err)
{
	if (!stdout_is_tty || verbose || debug)
		return;

	if (err)
		printf("\nSearch exited (%llu processed) with error %d: "
		       "\"%s\"\n", processed, err, strerror(err));
	else
		printf("\nSearch completed with no errors.             \n");
	fflush(stdout);
}

static void update_extent_search_status(unsigned long long processed)
{
	g_mutex_lock(&progress_mutex);
	search_processed += processed;
	g_cond_signal(&progress_updated);
	g_mutex_unlock(&progress_mutex);
}

static void wait_update_extent_search_status(GThreadPool *pool)
{
	uint64_t end_time = g_get_monotonic_time () + 1 * G_TIME_SPAN_SECOND;
	unsigned long long tmp, last = 0;

	if (!stdout_is_tty || verbose || debug)
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

static inline void mark_block_seen(uint64_t *off, struct file_block *block)
{
	/*
	 * Add 1 so the check in block_seen triggers on block->b_loff. This
	 * also allows it to catch the case where *off is initialized to 0 and
	 * b_loff == 0 but we haven't actually seen the block yet.
	 */
	if ((*off) < block->b_loff)
		*off = block->b_loff + 1;
}

static inline int block_seen(uint64_t off, struct file_block *block)
{
	if (off > block->b_loff)
		return 1;
	return 0;
}

static int walk_dupe_block(struct filerec *orig_file,
			   struct file_block *orig_file_block,
			   uint64_t *orig_best_off,
			   struct filerec *walk_file,
			   struct file_block *walk_file_block,
			   uint64_t *walk_best_off,
			   struct results_tree *res)
{
	struct file_block *orig = orig_file_block;
	struct file_block *block = walk_file_block;
	struct file_block *start[2] = { orig, block };
	struct file_block *end[2];
	struct running_checksum *csum;
	unsigned char match_id[DIGEST_LEN_MAX] = {0, };
	uint64_t orig_blkno, walk_blkno;
	struct rb_node *node;

	if (block_seen(*walk_best_off, block) ||
	    block_seen(*orig_best_off, orig))
		goto out;

	csum = start_running_checksum();

	abort_on(block->b_parent != orig->b_parent);

	while (block->b_parent == orig->b_parent) {
		mark_block_seen(walk_best_off, block);
		mark_block_seen(orig_best_off, orig);

		end[0] = orig;
		end[1] = block;

		add_to_running_checksum(csum, digest_len,
					block->b_parent->dl_hash);

		/*
		 * Check that we don't walk off either tree
		 */
		if (rb_next(&orig->b_file_next) == NULL ||
		    rb_next(&block->b_file_next) == NULL)
			break;

		orig_blkno = orig->b_loff;
		walk_blkno = block->b_loff;

		node = rb_next(&orig->b_file_next);
		orig = rb_entry(node, struct file_block, b_file_next);
		node = rb_next(&block->b_file_next);
		block = rb_entry(node, struct file_block, b_file_next);

		/*
		 * Check that our next blocks are contiguous wrt the
		 * old ones. If they aren't, then this has to be the
		 * end of our extents.
		 */
		if (orig->b_loff != (orig_blkno + blocksize) ||
		    block->b_loff != (walk_blkno + blocksize))
			break;
	}

	finish_running_checksum(csum, match_id);

	record_match(res, match_id, orig_file, walk_file,
		     start, end);
out:
	return 0;
}

/*
 * Start an extent search (with orig_block) at each block in our dups
 * list which is owned by walk_file.
 */
static void lookup_walk_file_hash_head(struct file_block *orig_block,
				       struct filerec *walk_file,
				       struct results_tree *res,
				       uint64_t *file_off, uint64_t *walk_off)
{
	struct dupe_blocks_list *parent = orig_block->b_parent;
	struct file_block *cur;
	struct file_hash_head *head = find_file_hash_head(parent, walk_file);

	/* find_file_dups should have checked this for us already */
	abort_on(head == NULL);

	list_for_each_entry(cur, &head->h_blocks, b_head_list) {
		/* Ignore self. Technically this shouldn't happen (see above)
		 * until we allow walking a file against itself. */
		if (cur == orig_block)
			continue;

		abort_on(cur->b_file != walk_file);

		if (walk_dupe_block(orig_block->b_file, orig_block, file_off,
				    walk_file, cur, walk_off, res))
			break;
	}
}

static void find_file_dupes(struct filerec *file, struct filerec *walk_file,
			    struct results_tree *res)
{
	struct file_block *cur;
	struct rb_node *node;
	uint64_t file_off = 0;
	uint64_t walk_off = 0;

	vprintf("Compare files \"%s\" and "
		"\"%s\"\n", file->filename, walk_file->filename);

	for (node = rb_first(&file->block_tree); node; node = rb_next(node)) {
		cur = rb_entry(node, struct file_block, b_file_next);

		if (block_seen(file_off, cur))
			continue;

		if (!file_in_dups_list(cur->b_parent, walk_file))
			continue;

		/*
		 * For each file block with the same hash:
		 *  - Traverse, along with original file until we have no match
		 *     - record
		 */
		lookup_walk_file_hash_head(cur, walk_file, res, &file_off,
					   &walk_off);
	}
}

struct find_dupes_cmp {
	struct filerec *file1;
	struct filerec *file2;
};
declare_alloc_tracking(find_dupes_cmp);

static int find_dupes_worker(struct find_dupes_cmp *cmp,
			     struct results_tree *res)
{
	struct filerec *file1 = cmp->file1;
	struct filerec *file2 = cmp->file2;

	free_find_dupes_cmp(cmp);

	find_file_dupes(file1, file2, res);
	update_extent_search_status(1);

	return mark_filerecs_compared(file1, file2);
}

static int push_compares(GThreadPool *pool, struct dupe_blocks_list *dups,
			 unsigned long long *pushed)
{
	int ret;
	struct filerec *file1, *file2, *tmp1, *tmp2;
	LIST_HEAD(cmp_files);
	unsigned int cmp_tot = 0;
	struct rb_node *node;
	struct file_hash_head *fh;
	GError *err = NULL;

	dprintf("Gather files from hash: ");
	if (debug)
		debug_print_digest_short(stdout, dups->dl_hash);
	dprintf(" (%llu identical extents)\n", dups->dl_num_elem);

	for (node = rb_first(&dups->dl_files_root); node; node = rb_next(node)) {
		fh = rb_entry(node, struct file_hash_head, h_node);
		file1 = fh->h_file;

		abort_on(!list_empty(&file1->tmp_list));
		list_add_tail(&file1->tmp_list, &cmp_files);
		cmp_tot++;
	}

	vprintf("Process %u files.\n", cmp_tot);

	list_for_each_entry_safe(file1, tmp1, &cmp_files, tmp_list) {
		file2 = file1;/* start from file1 for list iter */
		list_for_each_entry_safe_continue(file2, tmp2, &cmp_files,
						  tmp_list) {
			if (filerec_deduped(file1) && filerec_deduped(file2))
				continue;

			if (filerecs_compared(file1, file2))
				continue;

			if (dedupe_same_file || file1 != file2) {
				/* fire this off to a worker */
				struct find_dupes_cmp *cmp;

				cmp = malloc_find_dupes_cmp();
				if (!cmp)
					return ENOMEM;

				cmp->file1 = file1;
				cmp->file2 = file2;

				g_thread_pool_push(pool, cmp, &err);
				if (err) {
					free_find_dupes_cmp(cmp);

					fprintf(stderr,
						"Error from thread pool: %s\n ",
						err->message);
					g_error_free(err);
					return ENOMEM;
				}
				(*pushed)++;
			}
		}
		/*
		 * Throttle how many compares we're allocating and
		 * queuing, otherwise we run the risk of running into
		 * an ENOMEM. We can abuse the progress conditional
		 * wait queue for this as each worker thread will
		 * activate it on the way out.
		 */
		g_mutex_lock(&progress_mutex);
		while (g_thread_pool_unprocessed(pool) >= 4096)
			g_cond_wait(&progress_updated, &progress_mutex);
		g_mutex_unlock(&progress_mutex);

		cmp_tot--;
		list_del_init(&file1->tmp_list);
	}

	ret = 0;

	list_for_each_entry_safe(file1, tmp1, &cmp_files, tmp_list)
		list_del_init(&file1->tmp_list);

	return ret;
}

static int find_all_dupes_filewise(struct hash_tree *tree,
				   struct results_tree *res)
{
	int ret = 0;
	struct rb_root *root = &tree->root;
	struct rb_node *node = rb_first(root);
	struct dupe_blocks_list *dups;
	GError *err = NULL;
	GThreadPool *pool = NULL;
	unsigned long long pushed = 0;

	printf("Hashing completed. Using %u threads to calculate duplicate "
	       "extents. This may take some time.\n", cpu_threads);

	pool = g_thread_pool_new((GFunc) find_dupes_worker, res,
				 cpu_threads, TRUE, &err);
	if (err) {
		fprintf(stderr,
			"Unable to create find file dupes thread pool: %s\n",
			err->message);
		g_error_free(err);
		return ENOMEM;
	}

	while (1) {
		if (node == NULL)
			break;

		dups = rb_entry(node, struct dupe_blocks_list, dl_node);

		if (dups->dl_num_elem > 1) {
			ret = push_compares(pool, dups, &pushed);
			if (ret) {
				fprintf(stderr,
					"Error: %s while comparing files",
					strerror(ret));
				goto out;
			}
		}

		node = rb_next(node);
	}

	set_extent_search_status_count(pushed);
	wait_update_extent_search_status(pool);

out:
	g_thread_pool_free(pool, FALSE, TRUE);
	/*
	 * Save memory by freeing each filerec compared tree once all
	 * threads have finished.
	 */
	free_all_filerec_compared();
	return ret;
}

int find_all_dupes(struct hash_tree *tree, struct results_tree *res)
{
	int ret;
	struct filerec *file;

	if (block_dedupe) {
		sort_hashes_by_size(tree);
		return 0;
	} else {
		unsigned long long orig_extent_count = res->num_extents;

		ret = find_all_dupes_filewise(tree, res);

		vprintf("Removing overlapping extents\n");
		list_for_each_entry(file, &filerec_list, rec_list)
			remove_overlapping_extents(res, file);
		dprintf("Removed %llu extents (had %llu).\n",
			orig_extent_count - res->num_extents,
			orig_extent_count);

		return ret;
	}
}
