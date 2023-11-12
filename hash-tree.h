/*
 * hash-tree.h
 *
 * Copyright (C) 2016 SUSE.  All rights reserved.
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

#ifndef __HASH_TREE__
#define __HASH_TREE__
#include "debug.h"

#include "file_flags.h"

extern unsigned int blocksize;

struct hash_tree {
	struct rb_root	root;
	struct list_head size_list; /* This is for sorting by dl_num_elem  */
	uint64_t	num_blocks;
	uint64_t	num_hashes;
};

struct dupe_blocks_list {
	struct rb_node		dl_node; /* sorted by hash */
	struct list_head	dl_size_list; /* sorted by dl_num_elem */

	unsigned long long	dl_num_elem;
	struct list_head	dl_list;

	unsigned int		dl_num_files;
	struct rb_root		dl_files_root; /* stores file_hash_head nodes */

	unsigned char		dl_hash[DIGEST_LEN];
};

struct file_block {
	struct dupe_blocks_list	*b_parent;
	struct filerec	*b_file;
	uint64_t	b_loff;

	/*
	 * All blocks with this hash. Can be on dupe_blocks_list->dl_list, or
	 * block_dedupe_list->bd_block_list (see run_dedupe.c).
	 */
	struct list_head	b_list;

	struct rb_node		b_file_next; /* filerec->block_tree */
	struct list_head	b_head_list; /* file_hash_head->h_blocks */
};

struct dupe_blocks_list *find_block_list(struct hash_tree *tree,
					 unsigned char *digest);

int insert_hashed_block(struct hash_tree *tree, unsigned char *digest,
			struct filerec *file, uint64_t loff);
int remove_hashed_block(struct hash_tree *tree, struct file_block *block);
struct file_block *find_filerec_block(struct filerec *file,
				      uint64_t loff);

/*
 * We must call sort_file_hash_heads after inserting blocks into our
 * hash_tree. The scan in find_dupes requires them to be in order of
 * increasing offset.
 *
 * NOTE: Using an rbtree instead of doing the list sort winds up in a
 * large performance loss. The item walk in lookup_walk_file_hash_head()
 * is highly cpu bound so the extra instructions to do a linear tree walk
 * really shows up during benchmarking.
 */
void sort_file_hash_heads(struct hash_tree *tree);

/*
 * Stores a list of blocks with the same hash / filerec
 * combination. Each dupe_blocks_list keeps a tree of these (sorted by
 * file).
 *
 * This speeds up the extent search by allowing us to skip blocks that
 * don't belong to the file we are 'walking'. Blocks are inserted into
 * h_blocks in the same order they are given to insert_hashed_block()
 * (that is, in order of increasing offset).
 */
struct file_hash_head {
	struct filerec *h_file;
	struct rb_node h_node;
	struct list_head h_blocks;
};

struct file_hash_head *find_file_hash_head(struct dupe_blocks_list *dups,
					   struct filerec *file);

void init_hash_tree(struct hash_tree *tree);
void free_hash_tree(struct hash_tree *tree);
#endif /* __HASH_TREE__ */
