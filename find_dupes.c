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

	eoff[0] = blocksize + end[0]->b_loff;
	eoff[1] = blocksize + end[1]->b_loff;

	len = eoff[0] - soff[0];

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

static int walk_dupe_block(struct filerec *orig_file,
			   struct file_block *orig_file_block,
			   struct filerec *walk_file,
			   struct file_block *walk_file_block,
			   struct results_tree *res)
{
	struct file_block *orig = orig_file_block;
	struct file_block *block = walk_file_block;
	struct file_block *start[2] = { orig, block };
	struct file_block *end[2];
	struct running_checksum *csum;
	unsigned char match_id[DIGEST_LEN_MAX] = {0, };
	uint64_t orig_blkno, walk_blkno;

	if (block_seen(block) || block_seen(orig))
		goto out;

	csum = start_running_checksum();

	abort_on(block->b_parent != orig->b_parent);

	while (block->b_parent == orig->b_parent) {
		mark_block_seen(block);
		mark_block_seen(orig);

		end[0] = orig;
		end[1] = block;

		add_to_running_checksum(csum, digest_len,
					block->b_parent->dl_hash);

		/*
		 * This is kind of ugly, however it does correctly
		 * signify the end of our list.
		 */
		if (orig->b_file_next.next == &orig_file->block_list ||
		    block->b_file_next.next == &walk_file->block_list)
			break;

		orig_blkno = orig->b_loff;
		walk_blkno = block->b_loff;

		orig =	list_entry(orig->b_file_next.next, struct file_block,
				   b_file_next);
		block =	list_entry(block->b_file_next.next, struct file_block,
				   b_file_next);

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
				       struct results_tree *res)
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

		if (walk_dupe_block(orig_block->b_file, orig_block,
				    walk_file, cur, res))
			break;
	}
}

static void find_file_dupes(struct filerec *file, struct filerec *walk_file,
			    struct results_tree *res)
{
	struct file_block *cur;

	list_for_each_entry(cur, &file->block_list, b_file_next) {
		if (block_seen(cur))
			continue;

		if (!file_in_dups_list(cur->b_parent, walk_file))
			continue;

		/*
		 * For each file block with the same hash:
		 *  - Traverse, along with original file until we have no match
		 *     - record
		 */
		lookup_walk_file_hash_head(cur, walk_file, res);
	}
	clear_all_seen_blocks();
}

static int compare_files(struct results_tree *res, struct filerec *file1, struct filerec *file2)
{
	dprintf("comparing %s and %s\n", file1->filename, file2->filename);
	find_file_dupes(file1, file2, res);

	return mark_filerecs_compared(file1, file2);
}

static int walk_dupe_hashes(struct dupe_blocks_list *dups,
			    struct results_tree *res)
{
	int ret;
	struct file_block *block1, *block2;
	struct filerec *file1, *file2;

#define SKIP_FLAGS	(FILE_BLOCK_SKIP_COMPARE|FILE_BLOCK_HOLE)

	list_for_each_entry(block1, &dups->dl_list, b_list) {
		if (block1->b_flags & SKIP_FLAGS)
			continue;

		file1 = block1->b_file;
		block2 = block1;
		list_for_each_entry_continue(block2,
					     &dups->dl_list,
					     b_list) {
			if (block2->b_flags & SKIP_FLAGS)
				continue;

			/*
			 * Don't compare if both blocks are already
			 * marked as shared. In thoery however the
			 * blocks might not be shared with each other
			 * so we will want to account for this in a
			 * future change.
			 */
			if (do_lookup_extents &&
			    block1->b_flags & FILE_BLOCK_DEDUPED &&
			    block2->b_flags & FILE_BLOCK_DEDUPED)
				continue;

			file2 = block2->b_file;

			if (block_ever_seen(block2))
				continue;

			if (filerecs_compared(file1, file2))
				continue;

			if (file1 != file2) {
				ret = compare_files(res, file1, file2);
				if (ret)
					return ret;
				/*
				 * End here, after finding a set of
				 * duplicates. Future runs will see
				 * the deduped blocks and skip them,
				 * allowing us to dedupe any remaining
				 * extents (if any)
				 */
				break;
			}
		}
	}
	return 0;
}

static void update_extent_search_status(struct hash_tree *tree,
					unsigned long long processed)
{
	static int last_pos = -1;
	int i, pos;
	int width = 40;
	float progress;

	if (!fancy_status)
		return;

	progress = (float) processed / tree->num_blocks;
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

static void clear_extent_search_status(unsigned long long processed,
				       int err)
{
	if (!fancy_status)
		return;

	if (err)
		printf("\nSearch exited (%llu processed) with error %d: "
		       "\"%s\"\n", processed, err, strerror(err));
	else
		printf("\nSearch completed with no errors.             \n");
	fflush(stdout);
}

int find_all_dupes(struct hash_tree *tree, struct results_tree *res)
{
	int ret = 0;
	struct rb_root *root = &tree->root;
	struct rb_node *node = rb_first(root);
	struct dupe_blocks_list *dups;
	unsigned long long processed = 0;

	while (1) {
		if (node == NULL)
			break;

		dups = rb_entry(node, struct dupe_blocks_list, dl_node);

		update_extent_search_status(tree, processed);

		if (dups->dl_num_elem > 1) {
			ret = walk_dupe_hashes(dups, res);
			if (ret)
				goto out;
		}

		processed += dups->dl_num_elem;

		node = rb_next(node);
	}

	update_extent_search_status(tree, processed);
out:

	clear_extent_search_status(processed, ret);
	return ret;
}
