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
#ifdef	ITDEBUG
#include <inttypes.h>
#endif

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

static inline uint64_t extent_len(struct extent *extent)
{
	return extent->e_parent->de_len;
}

static inline uint64_t extent_end(struct extent *extent)
{
	return extent_len(extent) + extent->e_loff - 1;
}

static inline uint64_t extent_score(struct extent *extent)
{
	return extent->e_parent->de_score;
}

static struct extent *alloc_extent(struct filerec *file, uint64_t loff)
{
	struct extent *e = calloc_extent(1);

	if (e) {
		INIT_LIST_HEAD(&e->e_list);
		rb_init_node(&e->e_node);
		e->e_file = file;
		e->e_loff = loff;
		e->e_poff = e->e_plen = 0;
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

/*
 * This does not do all the work of insert_result(), just enough for
 * the dedupe phase of block-dedupe to work properly.
 */
int insert_one_result(struct results_tree *res, unsigned char *digest,
		      struct filerec *file, uint64_t startoff, uint64_t len)
{
	struct extent *extent = alloc_extent(file, startoff);
	struct dupe_extents *dext;

	if (!extent)
		return ENOMEM;

	dext = find_dupe_extents(res, digest, len);
	if (!dext) {
		dext = dupe_extents_new(res, digest, len);
		if (!dext)
			return ENOMEM;
	}

	abort_on(dext->de_len != len);

	insert_extent_list_free(dext, &extent);

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
		e0->e_itnode.start = e0->e_loff;
		e0->e_itnode.last = extent_end(e0);
		interval_tree_insert(&e0->e_itnode, &recs[0]->extent_tree);
#ifdef	ITDEBUG
		recs[0]->num_extents++;
#endif
	}
	if (e1) {
		if (add_score)
			dext->de_score += len;
		e1->e_itnode.start = e1->e_loff;
		e1->e_itnode.last = extent_end(e1);
		interval_tree_insert(&e1->e_itnode, &recs[1]->extent_tree);
#ifdef	ITDEBUG
		recs[1]->num_extents++;
#endif
	}

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
	interval_tree_remove(&extent->e_itnode, &extent->e_file->extent_tree);
#ifdef	ITDEBUG
	extent->e_file->num_extents--;
#endif
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
	return result;
}

#ifdef	ITDEBUG
static void print_all_extents(struct filerec *file)
{
	struct extent *extent;
	struct interval_tree_node *node;

	node = interval_tree_iter_first(&file->extent_tree, 0, -1ULL);
	while (node) {
		extent = container_of(node, struct extent, e_itnode);

		printf("file: %s, start: %"PRIu64", end: %"PRIu64" ep: %p\n",
		       file->filename, extent->e_loff, extent_end(extent),
		       extent);

		node = interval_tree_iter_next(node, 0, -1ULL);
	}
}
#endif	/* ITDEBUG */

static uint64_t __remove_overlaps(struct results_tree *res, struct filerec *file,
			      struct extent *extent)
{
	struct interval_tree_node *node;
	struct extent *found, *to_del;
	uint64_t start, end;

	start = extent->e_loff;
	end = extent_end(extent);

	node = interval_tree_iter_next(&extent->e_itnode, start, end);
	if (node) {
		to_del = found = container_of(node, struct extent, e_itnode);

		if (extent_score(extent) < extent_score(found))
			to_del = extent;

#ifdef	ITDEBUG
		printf("  extent: (%"PRIu64", %"PRIu64", %p)  found: "
		       "(%"PRIu64", %"PRIu64", %p)  to_del: %p  "
		       "greatest: %"PRIu64"\n", extent->e_loff,
		       extent_end(extent), extent, found->e_loff,
		       extent_end(found), found, to_del,
		       greatest);
#endif	/* ITDEBUG */

		remove_extent(res, to_del);
		return end;
	}

	return end + 1;
}

/*
 * At the end of this function the file should have zero dup extents
 * with overlapping ranges.
 */
void remove_overlapping_extents(struct results_tree *res, struct filerec *file)
{
	struct extent *extent;
	struct interval_tree_node *node;
	uint64_t start = 0, end = -1ULL;

	while (1) {
		node = interval_tree_iter_first(&file->extent_tree, start, end);
		if (!node)
			break;
		extent = container_of(node, struct extent, e_itnode);
#ifdef	ITDEBUG
		dprintf("check file %s, extents: %d, (%"PRIu64", %"PRIu64") "
			"ep: %p, search start: %"PRIu64", search end: "
			"%"PRIu64"\n", file->filename, file->num_extents,
			extent->e_loff, extent->e_itnode.last, extent, start,
			end);
#endif	/* ITDEBUG */

		start = __remove_overlaps(res, file, extent);
	}
}

void init_results_tree(struct results_tree *res)
{
	res->root = RB_ROOT;
	res->num_dupes = 0;
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
