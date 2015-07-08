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
static GMutex console_mutex;
static struct results_tree *results_tree;

void print_dupes_table(struct results_tree *res)
{
	struct rb_root *root = &res->root;
	struct rb_node *node = rb_first(root);
	struct dupe_extents *dext;
	struct extent *extent;

	printf("Simple read and compare of file data found %u instances of "
	       "extents that might benefit from deduplication.\n",
	       res->num_dupes);

	if (res->num_dupes == 0)
		return;

	while (1) {
		if (node == NULL)
			break;

		dext = rb_entry(node, struct dupe_extents, de_node);

		printf("Showing %u identical extents with id ",
		       dext->de_num_dupes);
		debug_print_digest_short(stdout, dext->de_hash);
		printf("\n");
		printf("Start\t\tLength\t\tFilename\n");
		list_for_each_entry(extent, &dext->de_extents, e_list) {
			printf("%s\t%s\t\"%s\"\n",
			       pretty_size(extent->e_loff),
			       pretty_size(dext->de_len),
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
	const char *status_str = "[unknown status]";

	while (!done) {
		done = pop_one_dedupe_result(ctxt, &target_status, &target_loff,
					     &target_bytes, &f);
		if (kern_bytes)
			*kern_bytes += target_bytes;

		if (target_status) {
			if (target_status == BTRFS_SAME_DATA_DIFFERS)
				status_str = "data changed";
			else if (target_status < 0)
				status_str = strerror(-target_status);
			printf("[%p] Dedupe for file \"%s\" had status (%d) "
			       "\"%s\".\n",
			       g_thread_self(), f->filename, target_status,
			       status_str);
		}
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
static int clean_deduped(struct dupe_extents **ret_dext)
{
	struct dupe_extents *dext = *ret_dext;
	struct extent *outer_extent, *outer_tmp;
	struct extent *inner_extent, *inner_tmp;
	bool next_removed = false;
	int left;

	if (!dext || list_empty(&dext->de_extents))
		return 0;

	list_for_each_entry_safe(outer_extent, outer_tmp,
				 &dext->de_extents, e_list) {
		if (next_removed)
			return 1;
		next_removed = false;

		list_for_each_entry_safe(inner_extent, inner_tmp,
					 &outer_extent->e_list, e_list) {
			/* We checked data up to outer_extent already */
			if (&inner_extent->e_list == &dext->de_extents)
				break;

			if (outer_extent == inner_extent)
				continue;
			if (outer_extent->e_poff == inner_extent->e_poff) {
				/* Outer loop next item removed, rerun. */
				if (inner_extent == outer_tmp)
					next_removed = true;

				g_mutex_lock(&mutex);
				left = remove_extent(results_tree, inner_extent);
				g_mutex_unlock(&mutex);
				if (left == 0) {
					*ret_dext = NULL;
					return 0;
				}
			}
		}
	}

	return 0;
}

#define	DEDUPE_EXTENTS_CLEANED	(-1)
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

	abort_on(dext->de_num_dupes < 2);

	/* Dedupe extents with id %s*/
	g_mutex_lock(&console_mutex);
	printf("[%p] Try to dedupe extents with id ", g_thread_self());
	debug_print_digest_short(stdout, dext->de_hash);
	printf("\n");
	g_mutex_unlock(&console_mutex);

	shared_prev = shared_post = 0ULL;
	add_shared_extents(dext, &shared_prev);

	/*
	 * Remove any extents which have already been deduped. This
	 * will free dext for us if the number of available extents
	 * goes below 2. If that happens, we return a special value so
	 * the caller knows not to reference dext any more.
	 */
	while(clean_deduped(&dext));
	if (!dext) {
		printf("[%p] Skipping - extents are already deduped.\n",
		       g_thread_self());
		return DEDUPE_EXTENTS_CLEANED;
	}
	list_for_each_entry(extent, &dext->de_extents, e_list) {
		if (list_is_last(&extent->e_list, &dext->de_extents))
			last = 1;

		ret = filerec_open_once(extent->e_file, target_rw, &open_files);
		if (ret) {
			fprintf(stderr, "%s: Skipping dedupe.\n",
				extent->e_file->filename);
			/*
			 * If this was our last duplicate extent in
			 * the list, and we added dupes from a
			 * previous iteration of the loop we need to
			 * run dedupe before exiting.
			 */
			if (ctxt && last)
				goto run_dedupe;
			continue;
		}

		to_add = extent;

		vprintf("[%p] Add extent for file \"%s\" at offset %s\n",
			g_thread_self(), to_add->e_file->filename,
			pretty_size(to_add->e_loff));

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
			g_mutex_lock(&console_mutex);
			printf("[%p] Dedupe %d extents (id: ", g_thread_self(),
			       ctxt->num_queued);
			debug_print_digest_short(stdout, dext->de_hash);
			printf(") with target: (%s, %s), "
			       "\"%s\"\n",
			       pretty_size(ctxt->orig_file_off),
			       pretty_size(ctxt->orig_len),
			       ctxt->ioctl_file->filename);
			g_mutex_unlock(&console_mutex);

			ret = dedupe_extents(ctxt);
			if (ret == 0) {
				process_dedupe_results(ctxt, kern_bytes);
			} else {
				ret = errno;
				fprintf(stderr,
					"FAILURE: Dedupe ioctl returns %d: %s\n",
					ret, strerror(ret));
			}
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
		if (ret == DEDUPE_EXTENTS_CLEANED)
			return 0;
		/* dedupe_extent_list already printed to stderr for us */
		return ret;
	}

	if (!list_empty(&dext->de_extents)) {
		g_mutex_lock(&mutex);
		dupe_extents_free(dext, results_tree);
		g_mutex_unlock(&mutex);
	}

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

		/*
		 * dext may be free'd by the dedupe threads, so get
		 * the next node now. In addition we want to lock
		 * around the rbtree code here so rb_erase doesn't
		 * change the tree underneath us.
		 */

		g_mutex_lock(&mutex);
		node = rb_next(node);
		g_mutex_unlock(&mutex);

		g_thread_pool_push(dedupe_pool, dext, &err);
		if (err) {
			fprintf(stderr, "Fatal error while deduping: %s\n",
				err->message);
			g_error_free(err);
			break;
		}
	}

	g_thread_pool_free(dedupe_pool, FALSE, TRUE);

	printf("Kernel processed data (excludes target files): %s\nComparison "
	       "of extent info shows a net change in shared extents of: %s\n",
	       pretty_size(counts.kern_bytes), pretty_size(counts.fiemap_bytes));
}

int fdupes_dedupe(void)
{
	int ret;
	struct filerec *file;
	struct dedupe_ctxt *ctxt = NULL;
	uint64_t bytes = 0;
	OPEN_ONCE(open_files);

	list_for_each_entry(file, &filerec_list, rec_list) {
		ret = filerec_open_once(file, 0, &open_files);
		if (ret) {
			fprintf(stderr, "%s: Skipping dedupe.\n",
				file->filename);
			continue;
		}

		printf("Queue entire file for dedupe: %s\n", file->filename);

		if (ctxt == NULL) {
			ctxt = new_dedupe_ctxt(MAX_DEDUPES_PER_IOCTL,
					       0, file->size, file);
			if (ctxt == NULL) {
				fprintf(stderr, "Out of memory while "
					"allocating dedupe context.\n");
				ret = ENOMEM;
				goto out;
			}
			continue;
		}

		ret = add_extent_to_dedupe(ctxt, 0, file);
		if (ret < 0) {
			fprintf(stderr, "%s: Request not queued.\n",
				file->filename);
			ret = ENOMEM;
			goto out;
		} else if (ret == 0 ||
			   list_is_last(&file->rec_list, &filerec_list)) {
			ret = dedupe_extents(ctxt);
			if (ret) {
				ret = errno;
				fprintf(stderr,
					"FAILURE: Dedupe ioctl returns %d: %s\n",
					ret, strerror(ret));
				goto out;
			}
			filerec_close_open_list(&open_files);
			process_dedupe_results(ctxt, &bytes);
			free_dedupe_ctxt(ctxt);
			ctxt = NULL;

			printf("Dedupe pass on %llu files completed\n",
			       num_filerecs);
		}
	}

	ret = 0;
out:
	filerec_close_open_list(&open_files);
	free_dedupe_ctxt(ctxt);
	free_all_filerecs();
	return ret;
}
