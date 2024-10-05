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
#include <linux/fiemap.h>

#include "kernel.h"
#include "rbtree.h"
#include "list.h"

#include "list.h"
#include "csum.h"	/* for DIGEST_LEN */

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
		rb_init_node(&e->e_node);
		e->e_file = file;
		e->e_loff = loff;
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
			cmp = memcmp(dext->de_hash, tmp->de_hash, DIGEST_LEN);
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
			cmp = memcmp(digest, dext->de_hash, DIGEST_LEN);
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
	/* We keep this tree free of duplicates  */
	if (insert_extent_rb(dext, *e) == 0) {
		(*e)->e_parent = dext;
		dext->de_num_dupes++;
		list_add_tail(&(*e)->e_list, &dext->de_extents);
		return;
	}

	free_extent(*e);
	*e = NULL;
}

static struct dupe_extents *dupe_extents_new(unsigned char *digest,
					     uint64_t len)
{
	struct dupe_extents *dext;

	dext = calloc_dupe_extents(1);
	if (!dext)
		return NULL;

	memcpy(dext->de_hash, digest, DIGEST_LEN);
	dext->de_len = len;
	dext->de_score = len;

	INIT_LIST_HEAD(&dext->de_extents);
	dext->de_extents_root = RB_ROOT;
	rb_init_node(&dext->de_node);
	g_mutex_init(&dext->de_mutex);

	return dext;
}

static struct dupe_extents *find_alloc_dext(struct results_tree *res,
					    unsigned char *digest,
					    uint64_t len, int *add_score)
{
	struct dupe_extents *dext, *new;

	if (add_score)
		*add_score = 1;

	g_mutex_lock(&res->tree_mutex);
	dext = find_dupe_extents(res, digest, len);
	g_mutex_unlock(&res->tree_mutex);
	if (!dext) {
		new = dupe_extents_new(digest, len);

		g_mutex_lock(&res->tree_mutex);
		dext = find_dupe_extents(res, digest, len);
		if (dext) {
			g_mutex_unlock(&res->tree_mutex);
			free_dupe_extents(new);
			return dext;
		}
		insert_dupe_extents(res, new);
		g_mutex_unlock(&res->tree_mutex);
		if (add_score)
			*add_score = 0;
		return new;
	}
	return dext;
}

/*
 * This does not do all the work of insert_result(), just enough for
 * the dedupe phase of block-dedupe to work properly.
 */
int insert_one_result(struct results_tree *res, unsigned char *digest,
		      struct filerec *file, uint64_t startoff, uint64_t len,
		      uint64_t poff)
{
	struct extent *extent = alloc_extent(file, startoff);
	struct dupe_extents *dext;

	if (!extent)
		return ENOMEM;

	extent_poff(extent) = poff;
	extent_plen(extent) = len;
	extent_shared_bytes(extent) = 0;
	dext = find_alloc_dext(res, digest, len, NULL);
	if (!dext)
		return ENOMEM;

	abort_on(dext->de_len != len);

	g_mutex_lock(&dext->de_mutex);
	insert_extent_list_free(dext, &extent);
	g_mutex_unlock(&dext->de_mutex);

	if (!extent)
		return 0;

	g_mutex_lock(&res->tree_mutex);
	res->num_extents++;
	g_mutex_unlock(&res->tree_mutex);

	return 0;
}

int insert_result(struct results_tree *res, unsigned char *digest,
		  struct filerec *recs[2], uint64_t startoff[2],
		  uint64_t endoff[2])
{
	struct extent *e0 = alloc_extent(recs[0], startoff[0]);
	struct extent *e1 = alloc_extent(recs[1], startoff[1]);
	struct dupe_extents *dext;
	uint64_t len = endoff[0] - startoff[0] + 1;
	int add_score;

	if (!e0 || !e1)
		return ENOMEM;

	dext = find_alloc_dext(res, digest, len, &add_score);
	if (!dext)
		return ENOMEM;

	abort_on(dext->de_len != len);

	g_mutex_lock(&dext->de_mutex);
	insert_extent_list_free(dext, &e0);
	insert_extent_list_free(dext, &e1);
	if (add_score) {
		if (e0)
			dext->de_score += len;
		if (e1)
			dext->de_score += len;
	}
	g_mutex_unlock(&dext->de_mutex);

	g_mutex_lock(&res->tree_mutex);
	if (e0)
		res->num_extents++;
	if (e1)
		res->num_extents++;
	g_mutex_unlock(&res->tree_mutex);

	return 0;
}

unsigned int remove_extent(struct results_tree *res, struct extent *extent)
{
	struct dupe_extents *p = extent->e_parent;
	struct rb_node *n;
	unsigned int result;

again:
	p->de_score -= p->de_len;
	p->de_num_dupes--;
	result = p->de_num_dupes;

	list_del_init(&extent->e_list);
	rb_erase(&extent->e_node, &p->de_extents_root);
	free_extent(extent);
	res->num_extents--;

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
	return result;
}

void init_results_tree(struct results_tree *res)
{
	res->root = RB_ROOT;
	res->num_dupes = 0;
	g_mutex_init(&res->tree_mutex);
	res->num_extents = 0;
}

void dupe_extents_free(struct dupe_extents *dext, struct results_tree *res)
{
	struct extent *extent;
	struct rb_node *n;
	int count;

	/*
	 * remove_extent will remove all stuff if there is less
	 * than one extent remaining
	 */
	do {
		n = rb_first(&dext->de_extents_root);
		extent = rb_entry(n, struct extent, e_node);
		count = remove_extent(res, extent);
	} while (count > 0);
}

void free_results_tree(struct results_tree *res)
{
	struct dupe_extents *de;
	struct rb_node *n = rb_first(&res->root);

	while (n) {
		de = rb_entry(n, struct dupe_extents, de_node);

		dupe_extents_free(de, res);

		n = rb_first(&res->root);
	}
}
