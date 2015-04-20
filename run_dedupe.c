/*
 * run_dedupe.c
 *
 * Implements dedupe of duplicate extents from our results tree
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>

#include <glib.h>

#include "rbtree.h"
#include "list.h"
#include "csum.h"
#include "filerec.h"
#include "hash-tree.h"
#include "results-tree.h"
#include "dedupe.h"
#include "util.h"
#include "memstats.h"
#include "debug.h"

#include "run_dedupe.h"

static GMutex mutex;
static struct results_tree *results_tree;

void print_dupes_table(struct results_tree *res)
{
	struct rb_root *root = &res->root;
	struct rb_node *node = rb_first(root);
	struct dupe_extents *dext;
	struct extent *extent;
	uint64_t calc_bytes = 0;

	printf("Simple read and compare of file data found %u instances of "
	       "extents that might benefit from deduplication.\n",
	       res->num_dupes);

	if (res->num_dupes == 0)
		return;

	while (1) {
		uint64_t len, len_blocks;

		if (node == NULL)
			break;

		dext = rb_entry(node, struct dupe_extents, de_node);

		len = dext->de_len;
		len_blocks = len / blocksize;
		calc_bytes += dext->de_score;

		vprintf("%u extents had length %llu Blocks (%llu) for a"
			" score of %llu.\n", dext->de_num_dupes,
			(unsigned long long)len_blocks,
			(unsigned long long)len,
			(unsigned long long)dext->de_score);
		if (debug) {
			printf("Hash is: ");
			debug_print_digest(stdout, dext->de_hash);
			printf("\n");
		}

		printf("Start\t\tLength\t\tFilename (%u extents)\n",
		       dext->de_num_dupes);
		list_for_each_entry(extent, &dext->de_extents, e_list) {
			printf("%s\t%s\t\"%s\"\n",
			       pretty_size(extent->e_loff),
			       pretty_size(len),
			       extent->e_file->filename);
		}

		node = rb_next(node);
	}
}

static void process_dedupe_results(struct dedupe_ctxt *ctxt,
				   uint64_t *kern_bytes)
{
	int done = 0;
	int target_status;
	uint64_t target_loff, target_bytes;
	struct filerec *f;

	while (!done) {
		done = pop_one_dedupe_result(ctxt, &target_status, &target_loff,
					     &target_bytes, &f);
		*kern_bytes += target_bytes;

		dprintf("\"%s\":\toffset: %llu\tprocessed bytes: %llu"
			"\tstatus: %d\n", f->filename,
			(unsigned long long)target_loff,
			(unsigned long long)target_bytes, target_status);
	}
}

static void add_shared_extents(struct dupe_extents *dext, uint64_t *shared)
{
	int ret = 0;
	struct extent *extent;
	struct filerec *file;

	list_for_each_entry(extent, &dext->de_extents, e_list) {
		file = extent->e_file;

		if (filerec_open(file, 0))
			continue;

		ret = filerec_count_shared(file, extent->e_loff, dext->de_len,
					   shared, &(extent->e_poff));
		if (ret) {
			fprintf(stderr, "%s: fiemap error %d: %s\n",
				extent->e_file->filename, ret, strerror(ret));
		}
		filerec_close(file);
	}
}

/*
 * Remove already deduped extents from list.
 * Returns 0 upon completion
 * If it returns 1, function might be called again
 */
static int clean_deduped(struct dupe_extents *dext)
{
	struct extent *outer_extent, *outer_tmp;
	struct extent *inner_extent, *inner_tmp;
	bool next_found = false;

	if (!dext)
		return 0;

	list_for_each_entry_safe(outer_extent, outer_tmp,
				 &dext->de_extents, e_list) {
		if (next_found){
			return 1;
		}
		next_found = false;
		list_for_each_entry_safe(inner_extent, inner_tmp,
					 &dext->de_extents, e_list) {
			if (outer_extent == inner_extent)
				continue;
			if (outer_extent->e_poff == inner_extent->e_poff) {
				/* Outer loop next item removed, rerun. */
				if (inner_extent == outer_tmp)
					next_found = true;

				g_mutex_lock(&mutex);
				remove_extent(results_tree, inner_extent);
				g_mutex_unlock(&mutex);
			}
		}
	}

	return 0;
}

static int dedupe_extent_list(struct dupe_extents *dext, uint64_t *fiemap_bytes,
			      uint64_t *kern_bytes)
{
	int ret = 0;
	int last = 0;
	int rc;
	uint64_t shared_prev, shared_post;
	struct extent *extent;
	struct dedupe_ctxt *ctxt = NULL;
	uint64_t len = dext->de_len;
	OPEN_ONCE(open_files);
	struct extent *prev = NULL;
	struct extent *to_add;
	struct extent *tmp;

	abort_on(dext->de_num_dupes < 2);

	shared_prev = shared_post = 0ULL;
	add_shared_extents(dext, &shared_prev);

	/* First pass: try to open all files, remove missing */
	list_for_each_entry_safe(extent, tmp, &dext->de_extents, e_list) {
		ret = filerec_open_once(extent->e_file, target_rw, &open_files);
		if (ret) {
			fprintf(stderr, "%s: Skipping dedupe.\n",
				extent->e_file->filename);
			g_mutex_lock(&mutex);
			remove_extent(results_tree, extent);
			g_mutex_unlock(&mutex);
		}
	}

	/* Second pass: remove already deduped extents. */
	while(clean_deduped(dext));

	if (list_empty(&dext->de_extents))
		return 0;

	list_for_each_entry(extent, &dext->de_extents, e_list) {
		vprintf("%s\tstart block: %llu (%llu)\n",
			extent->e_file->filename,
			(unsigned long long)extent->e_loff / blocksize,
			(unsigned long long)extent->e_loff);

		if (list_is_last(&extent->e_list, &dext->de_extents))
			last = 1;

		to_add = extent;

		if (ctxt == NULL) {
			ctxt = new_dedupe_ctxt(dext->de_num_dupes,
					       extent->e_loff, len,
					       extent->e_file);
			if (ctxt == NULL) {
				fprintf(stderr, "Out of memory while "
					"allocating dedupe context.\n");
				ret = ENOMEM;
				goto out;
			}

			if (!last) {
				/*
				 * We added our file already here via
				 * new_dedupe_ctxt, so go to the next
				 * loop iteration.
				 */
				continue;
			}

			/*
			 * We started a new context, but only have one
			 * extent left to dedupe (need at least
			 * 2). This is pretty rare but instead of
			 * leaving it not-deduped, we can pick the
			 * most recent extent off the list and re-add
			 * that. The old extent won't be deduped again
			 * but this one will.
			 *
			 * This won't work if we haven't deduped
			 * anything yet. If prev doesn't exist, we
			 * skip this and let the dedupe code below
			 * clean up for us.
			 */
			if (prev == NULL)
				goto run_dedupe;
			to_add = prev; /* The ole' extent switcharoo */
		}
		prev = extent; /* save previous extent for condition above */

		rc = add_extent_to_dedupe(ctxt, to_add->e_loff, to_add->e_file);
		if (rc) {
			if (rc < 0) {
				/* This can only be ENOMEM. */
				fprintf(stderr, "%s: Request not queued.\n",
					to_add->e_file->filename);
				ret = ENOMEM;
				goto out;
			}

			if (last)
				goto run_dedupe;
			continue;
		}

run_dedupe:

		/*
		 * We can get here with only the target extent (0
		 * queued) for many reasons. Skip the dedupe in that
		 * case but always do cleanup.
		 */
		if (ctxt->num_queued) {
			printf("[%p] Dedupe %d extents with target: (%s, %s), "
			       "\"%s\"\n",
			       g_thread_self(),
			       ctxt->num_queued,
			       pretty_size(ctxt->orig_file_off),
			       pretty_size(ctxt->orig_len),
			       ctxt->ioctl_file->filename);

			ret = dedupe_extents(ctxt);
			if (ret) {
				ret = errno;
				fprintf(stderr,
					"FAILURE: Dedupe ioctl returns %d: %s\n",
					ret, strerror(ret));
			}

			process_dedupe_results(ctxt, kern_bytes);
		}

		filerec_close_open_list(&open_files);
		free_dedupe_ctxt(ctxt);
		ctxt = NULL;
	}

	abort_on(ctxt != NULL);
	abort_on(!RB_EMPTY_ROOT(&open_files.root));

	add_shared_extents(dext, &shared_post);
	/*
	 * It's entirely possible that some other process is
	 * manipulating files underneath us. Take care not to
	 * report some randomly enormous 64 bit value.
	 */
	if (shared_prev  < shared_post)
		*fiemap_bytes += shared_post - shared_prev;

	/* The only error we want to bubble up is ENOMEM */
	ret = 0;
out:
	/*
	 * ENOMEM error during context allocation may have caused open
	 * files to stay in our list.
	 */
	filerec_close_open_list(&open_files);
	/*
	 * We might have allocated a context above but not
	 * filled it with any extents, make sure to free it
	 * here.
	 */
	free_dedupe_ctxt(ctxt);

	abort_on(!RB_EMPTY_ROOT(&open_files.root));

	return ret;
}

static GMutex dedupe_counts_mutex;
struct dedupe_counts {
	uint64_t	kern_bytes;
	uint64_t	fiemap_bytes;
};

static int dedupe_worker(struct dupe_extents *dext,
			 struct dedupe_counts *counts)
{
	int ret;
	uint64_t fiemap_bytes = 0ULL;
	uint64_t kern_bytes = 0ULL;

	ret = dedupe_extent_list(dext, &fiemap_bytes, &kern_bytes);
	if (ret) {
		/* dedupe_extent_list already printed to stderr for us */
		return ret;
	}

	g_mutex_lock(&mutex);
	dupe_extents_free(dext, results_tree);
	g_mutex_unlock(&mutex);

	g_mutex_lock(&dedupe_counts_mutex);
	counts->fiemap_bytes += fiemap_bytes;
	counts->kern_bytes += kern_bytes;
	g_mutex_unlock(&dedupe_counts_mutex);

	return 0;
}

static GThreadPool *dedupe_pool = NULL;

void dedupe_results(struct results_tree *res)
{
	struct rb_root *root = &res->root;
	struct rb_node *node = rb_first(root);
	struct dupe_extents *dext;
	struct dedupe_counts counts = { 0ULL, };
	GError *err = NULL;

	results_tree = res;

	print_dupes_table(res);

	if (RB_EMPTY_ROOT(root)) {
		printf("Nothing to dedupe.\n");
		return;
	}

	printf("Using %u threads for dedupe phase\n", io_threads);

	dedupe_pool = g_thread_pool_new((GFunc) dedupe_worker, &counts,
					io_threads, TRUE, &err);
	if (err) {
		fprintf(stderr, "Unable to create dedupe thread pool: %s\n",
			err->message);
		g_error_free(err);
		return;
	}

	while (node) {
		dext = rb_entry(node, struct dupe_extents, de_node);

		g_thread_pool_push(dedupe_pool, dext, &err);
		if (err) {
			fprintf(stderr, "Fatal error while deduping: %s\n",
				err->message);
			g_error_free(err);
			break;
		}

		node = rb_next(node);
	}

	g_thread_pool_free(dedupe_pool, FALSE, TRUE);

	printf("Kernel processed data (excludes target files): %s\nComparison "
	       "of extent info shows a net change in shared extents of: %s\n",
	       pretty_size(counts.kern_bytes), pretty_size(counts.fiemap_bytes));
}
