/*
 * results-tree.c
 *
 * Copyright (C) 2013 SUSE.  All rights reserved.
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

#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "kernel.h"
#include "rbtree.h"
#include "list.h"

#include "csum.h"	/* for digest_len variable and DIGEST_LEN_MAX */

#include "filerec.h"
#include "results-tree.h"

#include "debug.h"
#include "memstats.h"

declare_alloc_tracking(dupe_extents);
declare_alloc_tracking(extent);

static struct extent *alloc_extent(struct filerec *file, uint64_t loff)
{
	struct extent *e = calloc_extent(1);

	if (e) {
		INIT_LIST_HEAD(&e->e_list);
		INIT_LIST_HEAD(&e->e_file_extents);
		rb_init_node(&e->e_node);
		e->e_file = file;
		e->e_loff = loff;
		e->e_poff = 0;
	}
	return e;
}

static int extents_rb_cmp(struct extent *e1, struct extent *e2)
{
	if (e1->e_file > e2->e_file)
		return -1;
	if (e1->e_file < e2->e_file)
		return 1;
	if (e1->e_loff > e2->e_loff)
		return -1;
	if (e1->e_loff < e2->e_loff)
		return 1;
	return 0;
}

static int insert_extent_rb(struct dupe_extents *dext, struct extent *e)
{
	int res;
	struct extent *tmp;
	struct rb_node **p = &dext->de_extents_root.rb_node;
	struct rb_node *parent = NULL;

	while (*p) {
		parent = *p;

		tmp = rb_entry(parent, struct extent, e_node);
		res = extents_rb_cmp(tmp, e);
		if (res < 0) {
			p = &(*p)->rb_left;
		} else if (res > 0) {
			p = &(*p)->rb_right;
		} else {
			return 1;
		}
	}

	rb_link_node(&e->e_node, parent, p);
	rb_insert_color(&e->e_node, &dext->de_extents_root);
	return 0;
}

static int insert_extent_list(struct dupe_extents *dext, struct extent *e)
{
	/* We keep this tree free of duplicates  */
	if (insert_extent_rb(dext, e) == 0) {
		e->e_parent = dext;
		dext->de_num_dupes++;
		list_add_tail(&e->e_list, &dext->de_extents);
		return 0;
	}

	return 1;
}

static void insert_dupe_extents(struct results_tree *res,
				struct dupe_extents *dext)
{
	struct rb_node **p = &res->root.rb_node;
	struct rb_node *parent = NULL;
	struct dupe_extents *tmp;
	int cmp; 

	while (*p) {
		parent = *p;

		tmp = rb_entry(parent, struct dupe_extents, de_node);
		if (dext->de_len < tmp->de_len)
			p = &(*p)->rb_left;
		else if (dext->de_len > tmp->de_len)
			p = &(*p)->rb_right;
		else {
			cmp = memcmp(dext->de_hash, tmp->de_hash, digest_len);
			if (cmp < 0)
				p = &(*p)->rb_left;
			else if (cmp > 0)
				p = &(*p)->rb_right;
			else
				abort_lineno(); /* We should never find a duplicate */
		}
	}

	res->num_dupes++;
	rb_link_node(&dext->de_node, parent, p);
	rb_insert_color(&dext->de_node, &res->root);
}

static struct dupe_extents *find_dupe_extents(struct results_tree *res,
				      unsigned char *digest, uint64_t len)
{
	struct rb_node *n = res->root.rb_node;
	struct dupe_extents *dext;
	int cmp;

	while (n) {
		dext = rb_entry(n, struct dupe_extents, de_node);

		/* Compare by length first, then use digest to drill
		 * down to a match */
		if (len < dext->de_len)
			n = n->rb_left;
		else if (len > dext->de_len)
			n = n->rb_right;
		else {
			cmp = memcmp(digest, dext->de_hash, digest_len);
			if (cmp < 0)
				n = n->rb_left;
			else if (cmp > 0)
				n = n->rb_right;
			else
				return dext;
		}

	}
	return NULL;
}

static void insert_extent_list_free(struct dupe_extents *dext,
				    struct extent **e)
{
	if (insert_extent_list(dext, *e)) {
		free_extent(*e);
		*e = NULL;
	}
}

static struct dupe_extents *dupe_extents_new(struct results_tree *res,
					     unsigned char *digest,
					     uint64_t len)
{
	struct dupe_extents *dext;

	dext = calloc_dupe_extents(1);
	if (!dext)
		return NULL;

	memcpy(dext->de_hash, digest, digest_len);
	dext->de_len = len;
	INIT_LIST_HEAD(&dext->de_extents);
	dext->de_extents_root = RB_ROOT;

	rb_init_node(&dext->de_node);

	insert_dupe_extents(res, dext);

	dext->de_score = len;

	return dext;
}

int insert_result(struct results_tree *res, unsigned char *digest,
		  struct filerec *recs[2], uint64_t startoff[2],
		  uint64_t endoff[2])
{
	struct extent *e0 = alloc_extent(recs[0], startoff[0]);
	struct extent *e1 = alloc_extent(recs[1], startoff[1]);
	struct dupe_extents *dext;
	uint64_t len = endoff[0] - startoff[0];
	int add_score = 1;

	if (!e0 || !e1)
		return ENOMEM;

	dext = find_dupe_extents(res, digest, len);
	if (!dext) {
		dext = dupe_extents_new(res, digest, len);
		if (!dext)
			return ENOMEM;
		add_score = 0;
	}

	abort_on(dext->de_len != len);

	insert_extent_list_free(dext, &e0);
	insert_extent_list_free(dext, &e1);

	if (e0) {
		if (add_score)
			dext->de_score += len;
		list_add_tail(&e0->e_file_extents, &recs[0]->extent_list);
	}
	if (e1) {
		if (add_score)
			dext->de_score += len;
		list_add_tail(&e1->e_file_extents, &recs[1]->extent_list);
	}

	return 0;
}

static uint64_t extent_len(struct extent *extent)
{
	return extent->e_parent->de_len;
}

static void remove_extent(struct results_tree *res, struct extent *extent)
{
	struct dupe_extents *p = extent->e_parent;
	struct rb_node *n;

again:
	p->de_score -= p->de_len;
	p->de_num_dupes--;

	list_del_init(&extent->e_list);
	list_del_init(&extent->e_file_extents);
	rb_erase(&extent->e_node, &p->de_extents_root);
	free_extent(extent);

	if (p->de_num_dupes == 1) {
		/* It doesn't make sense to have one extent in a dup
		 * list. */
		abort_on(RB_EMPTY_ROOT(&p->de_extents_root));/* logic error */

		n = rb_first(&p->de_extents_root);
		extent = rb_entry(n, struct extent, e_node);
		goto again;
	}

	if (p->de_num_dupes == 0) {
		rb_erase(&p->de_node, &res->root);
		free_dupe_extents(p);
		res->num_dupes--;
	}
}

static int compare_extent(struct results_tree *res,
			  struct extent *extent,
			  struct list_head *head)
{
	struct extent *pos = extent;
	uint64_t pos_end, extent_end;
	struct list_head *next = extent->e_file_extents.next;

	list_for_each_entry_continue(pos, head, e_file_extents) {
		/* This is a logic error - we shouldn't loop back on
		 * ourselves. */
		abort_on(pos == extent);

//		if (pos->e_loff == extent->e_loff
//		    && extent_len(pos) == extent_len(extent))
//			continue; /* Same extent? Skip. */

		pos_end = pos->e_loff + extent_len(pos) - 1;
		extent_end = extent->e_loff + extent_len(extent) - 1;

		if (pos_end < extent->e_loff ||
		    pos->e_loff > extent_end)
			continue; /* Extents don't overlap */

		if (extent->e_parent->de_score <= pos->e_parent->de_score) {
			/* remove extent */
			remove_extent(res, extent);
		} else {
			/* remove pos */
			if (pos == list_entry(next, struct extent,
					      e_file_extents))
				next = pos->e_file_extents.next;
			remove_extent(res, pos);
		}
		return 1;
	}

	return 0;
}

void remove_overlapping_extents(struct results_tree *res, struct filerec *file)
{
	struct extent *orig;
	struct list_head *next;

	if (list_empty(&file->extent_list))
		return;

restart:
	next = file->extent_list.next;
	while (next != &file->extent_list) {
		orig = list_entry(next, struct extent, e_file_extents);

		/*
		 * Re-start the search if we wound up deleting items -
		 * compare_extent could have deleted up to two items,
		 * either of which could be our loop cursor.
		 */
		if (compare_extent(res, orig, &file->extent_list))
			goto restart;

		next = next->next;
	}
}

void init_results_tree(struct results_tree *res)
{
	res->root = RB_ROOT;
	res->num_dupes = 0;
}
