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
					   shared);
		if (ret) {
			fprintf(stderr, "%s: fiemap error %d: %s\n",
				extent->e_file->filename, ret, strerror(ret));
		}
		filerec_close(file);
	}
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
	LIST_HEAD(open_files);
	struct filerec *file;
	struct extent *prev = NULL;
	struct extent *to_add;

	abort_on(dext->de_num_dupes < 2);

	shared_prev = shared_post = 0ULL;
	add_shared_extents(dext, &shared_prev);

	list_for_each_entry(extent, &dext->de_extents, e_list) {
		vprintf("%s\tstart block: %llu (%llu)\n",
			extent->e_file->filename,
			(unsigned long long)extent->e_loff / blocksize,
			(unsigned long long)extent->e_loff);

		if (list_is_last(&extent->e_list, &dext->de_extents))
			last = 1;

		to_add = extent;
		file = extent->e_file;
		ret = filerec_open_once(file, target_rw, &open_files);
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
			 */
			abort_on(!prev);
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
		 * We can get here with only the target extent (0 queued) if
		 * filerec_open_list fails on the 2nd (and last)
		 * extent.
		 */
		if (ctxt->num_queued) {
			printf("Dedupe %d extents with target: (%s, %s), "
			       "\"%s\"\n",
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

		filerec_close_files_list(&open_files);
		free_dedupe_ctxt(ctxt);
		ctxt = NULL;
	}

	abort_on(ctxt != NULL);
	abort_on(!list_empty(&open_files));

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
	filerec_close_files_list(&open_files);
	/*
	 * We might have allocated a context above but not
	 * filled it with any extents, make sure to free it
	 * here.
	 */
	free_dedupe_ctxt(ctxt);

	abort_on(!list_empty(&open_files));

	return ret;
}

void dedupe_results(struct results_tree *res)
{
	int ret;
	struct rb_root *root = &res->root;
	struct rb_node *node = rb_first(root);
	struct dupe_extents *dext;
	uint64_t fiemap_bytes = 0;
	uint64_t kern_bytes = 0;

	print_dupes_table(res);

	if (RB_EMPTY_ROOT(root)) {
		printf("Nothing to dedupe.\n");
		return;
	}

	while (node) {
		dext = rb_entry(node, struct dupe_extents, de_node);

		ret = dedupe_extent_list(dext, &fiemap_bytes, &kern_bytes);
		if (ret)
			break;

		node = rb_next(node);
	}

	printf("Kernel processed data (excludes target files): %s\nComparison "
	       "of extent info shows a net change in shared extents of: %s\n",
	       pretty_size(kern_bytes), pretty_size(fiemap_bytes));
}
