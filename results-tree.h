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

#include <glib.h>

#include "interval_tree.h"

struct results_tree {
	struct rb_root	root;
	unsigned int	num_dupes;
	GMutex		tree_mutex;
	unsigned long long	num_extents;
};

struct dupe_extents {
	unsigned int	de_num_dupes;
	uint64_t	de_len;
	unsigned char		de_hash[DIGEST_LEN];

	uint64_t	de_score;

	struct list_head	de_extents;
	struct rb_root		de_extents_root;

	struct rb_node		de_node;
	GMutex			de_mutex;
};

struct extent_dedupe_info;
struct extent	{
	struct dupe_extents	*e_parent;

	uint64_t	e_loff;
	struct filerec	*e_file;

	struct list_head	e_list; /* For de_extents */
	struct rb_node		e_node; /* For de_extents_root */

	/* Each file keeps a tree of its own dupes. This makes it
	 * easier to remove overlapping duplicates. */
	struct interval_tree_node e_itnode;

#define	E_MAY_DELETE	0x01
	int			e_flags;

	/*
	 * Physical offset and length are used to figure out whether
	 * we have already deduped this extent yet.
	 */
	uint64_t		e_poff;
	uint64_t		e_plen;
	uint64_t		e_shared_bytes;
};
#define extent_len(_e)	((_e)->e_parent->de_len)
#define extent_poff(_e)	((_e)->e_poff)
#define extent_plen(_e)	((_e)->e_plen)
#define extent_shared_bytes(_e)	((_e)->e_shared_bytes)

/*
 * insert_result and insert_one_result use the object mutexes above
 * and are thread-safe.
 */
int insert_result(struct results_tree *res, unsigned char *digest,
		  struct filerec *recs[2], uint64_t startoff[2],
		  uint64_t endoff[2]);
int insert_one_result(struct results_tree *res, unsigned char *digest,
		      struct filerec *file, uint64_t startoff, uint64_t len,
		      uint64_t poff, int flags);
void remove_overlapping_extents(struct results_tree *res, struct filerec *file);

void init_results_tree(struct results_tree *res);
void free_results_tree(struct results_tree *res);
void dupe_extents_free(struct dupe_extents *dext, struct results_tree *res);

unsigned int remove_extent(struct results_tree *res, struct extent *extent);
#endif /* __RESULTS_TREE__ */
