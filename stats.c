/*
 * stats.c
 *
 * Copyright (C) 2017 SUSE.  All rights reserved.
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

#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>

#include "rbtree.h"
#include "list.h"
#include "interval_tree.h"

#include "csum.h"
#include "filerec.h"
#include "hash-tree.h"
#include "results-tree.h"
#include "interval_tree.h"
#include "debug.h"

extern unsigned int blocksize;

static void count_filerec_duped_bytes(struct filerec *file, uint64_t *bytes)
{
	struct rb_node *node;
	struct file_block *block;
	for (node = rb_first(&file->block_tree); node; node = rb_next(node)) {
		block = rb_entry(node, struct file_block, b_file_next);

		*bytes += block_len(block);
	}
}

static void count_filerec_deduped_bytes(struct filerec *file, uint64_t *bytes)
{
	struct extent *extent = NULL;
	struct interval_tree_node *node;
	uint64_t start, end;
	uint64_t this_start, this_end;

	start = end = 0;
	for (node = interval_tree_iter_first(&file->extent_tree, 0, -1ULL);
	     node; node = interval_tree_iter_next(node, 0, -1ULL)) {
		extent = container_of(node, struct extent, e_itnode);
		this_start = extent->e_loff;
		this_end = this_start + extent->e_parent->de_len - 1;

		if (start == 0 && start == end) {
			start = this_start;
			end = this_end;
			continue;
		}

		/* any overlap? then adjust start/end */
		if (this_start <= end && this_end >= start) {
			if (this_start < start)
				start = this_start;
			if (this_end > end)
				end = this_end;
		} else {
			/* new extent */
			*bytes += end - start + 1;
			start = this_start;
			end = this_end;
		}
	}

	if (extent) /* this is a canary to tell if we entered the loop above */
		*bytes += end - start + 1;
}

static void print_all_blocks(struct filerec *file)
{
	struct rb_node *node;
	struct file_block *block;

	printf(" blocks: ");
	for (node = rb_first(&file->block_tree); node; node = rb_next(node)) {
		block = rb_entry(node, struct file_block, b_file_next);

		printf("%"PRIu64" ", block->b_loff);
	}
	printf("\n");
}

static void print_all_extents(struct filerec *file)
{
	struct extent *extent = NULL;
	struct interval_tree_node *node;

	printf(" extents: ");
	for (node = interval_tree_iter_first(&file->extent_tree, 0, -1ULL);
	     node; node = interval_tree_iter_next(node, 0, -1ULL)) {
		extent = container_of(node, struct extent, e_itnode);

		printf("(%"PRIu64", %"PRIu64") ", extent->e_loff,
		       extent->e_loff + extent->e_parent->de_len - 1);
	}
	printf("\n");
}

void run_filerec_stats(void)
{
	struct filerec *file;
	uint64_t dupe_bytes, deduped_bytes;
	uint64_t total_dupe, total_deduped;

	total_dupe = total_deduped = 0;

	printf("---- FIND DUPES STATS ----\n");
	printf("<filename>, <dupe bytes found>, <dupe bytes to submit>\n");

	list_for_each_entry(file, &filerec_list, rec_list) {
		dupe_bytes = deduped_bytes = 0;

		count_filerec_duped_bytes(file, &dupe_bytes);
		if (!dupe_bytes)
			continue;

		count_filerec_deduped_bytes(file, &deduped_bytes);

		printf("%s, %"PRIu64", %"PRIu64"\n", file->filename, dupe_bytes,
			deduped_bytes);

		if (verbose) {
			print_all_blocks(file);
			print_all_extents(file);
		}
		total_dupe += dupe_bytes;
		total_deduped += deduped_bytes;
	}
	printf("Total bytes to submit: %"PRIu64"\t Total dupe bytes: %"PRIu64
	       "\t%%%.0f deduped.\n", total_deduped, total_dupe,
	       (double)total_deduped / (double)total_dupe * 100);
	printf("---- END FIND DUPES STATS ----\n");
}
