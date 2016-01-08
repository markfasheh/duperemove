/*
 * results-tree.h
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
 *
 */

#ifndef __RESULTS_TREE_
#define __RESULTS_TREE_

struct results_tree {
	struct rb_root	root;
	unsigned int	num_dupes;
};

struct dupe_extents {
	unsigned int	de_num_dupes;
	uint64_t	de_len;
	unsigned char		de_hash[DIGEST_LEN_MAX];

	uint64_t	de_score;

	struct list_head	de_extents;
	struct rb_root		de_extents_root;

	struct rb_node		de_node;
};

struct extent	{
	struct dupe_extents	*e_parent;

	uint64_t	e_loff;
	struct filerec	*e_file;

	struct list_head	e_list; /* For de_extents */
	struct rb_node		e_node; /* For de_extents_root */

	/* Each file keeps a list of it's own dupes. This makes it
	 * easier to remove overlapping duplicates. */
	struct list_head	e_file_extents; /* filerec->extent_list */

	/*
	 * Physical offset and length are used to figure out whether
	 * we have already deduped this extent yet.
	 *
	 * e_plen is the length of the *first* physical extent in our
	 * range, not a total of all extents covered.
	 */
	uint64_t		e_poff;
	uint64_t		e_plen;
};

/* endoff is NOT inclusive! */
int insert_result(struct results_tree *res, unsigned char *digest,
		  struct filerec *recs[2], uint64_t startoff[2],
		  uint64_t endoff[2]);

void remove_overlapping_extents(struct results_tree *res, struct filerec *file);

void init_results_tree(struct results_tree *res);
void dupe_extents_free(struct dupe_extents *dext, struct results_tree *res);

unsigned int remove_extent(struct results_tree *res, struct extent *extent);
#endif /* __RESULTS_TREE__ */
