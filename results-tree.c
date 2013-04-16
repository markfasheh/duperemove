#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "kernel.h"
#include "rbtree.h"
#include "list.h"

#include "csum.h"	/* for digest_len variable and DIGEST_LEN_MAX */

#include "results-tree.h"

static struct extent *_alloc_extent(void)
{
	struct extent *e = calloc(1, sizeof(*e));

	INIT_LIST_HEAD(&e->e_list);
	INIT_LIST_HEAD(&e->e_file_extents);

	return e;
}

static struct extent *alloc_extent(unsigned int fileid, uint64_t loff)
{
	struct extent *e = _alloc_extent();

	if (e) {
		e->e_file = fileid;
		e->e_loff = loff;
	}
	return e;
}

static int insert_extent_list(struct dupe_extents *dext, struct extent *e)
{
	struct extent *tmp;

	list_for_each_entry(tmp, &dext->de_extents, e_list) {
		if (tmp->e_loff == e->e_loff && tmp->e_file == e->e_file)
			return 1;
	}

	e->e_parent = dext;
	dext->de_num_dupes++;
	list_add_tail(&e->e_list, &dext->de_extents);

	dext->de_score += dext->de_len;

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
			cmp = memcmp(dext->de_hash, tmp->de_hash, digest_len);
			if (cmp < 0)
				p = &(*p)->rb_left;
			else if (cmp > 0)
				p = &(*p)->rb_right;
			else
				abort(); /* We should never find a duplicate */
		}
	}

	res->num_dupes++;
	rb_link_node(&dext->de_node, parent, p);
	rb_insert_color(&dext->de_node, &res->root);
}

struct dupe_extents *find_dupe_extents(struct results_tree *res,
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
		free(*e);
		*e = NULL;
	}
}

int insert_result(struct results_tree *res, unsigned char *digest,
		  int fileids[2], uint64_t startoff[2], uint64_t endoff[2],
		  struct list_head *head[2])
{
	struct extent *e0 = alloc_extent(fileids[0], startoff[0]);
	struct extent *e1 = alloc_extent(fileids[1], startoff[1]);
	struct dupe_extents *dext;
	uint64_t len = endoff[0] - startoff[0];

	if (!e0 || !e1)
		return ENOMEM;

	dext = find_dupe_extents(res, digest, len);
	if (!dext) {
		dext = calloc(1, sizeof(*dext));
		if (!dext)
			return ENOMEM;

		memcpy(dext->de_hash, digest, digest_len);
		dext->de_len = len;
		INIT_LIST_HEAD(&dext->de_extents);

		insert_dupe_extents(res, dext);
	}

	if (dext->de_len != len)
		abort();

	insert_extent_list_free(dext, &e0);
	insert_extent_list_free(dext, &e1);

	if (head && e0)
		list_add_tail(&e0->e_file_extents, head[0]);
	if (head && e1)
		list_add_tail(&e1->e_file_extents, head[1]);

	return 0;
}

static uint64_t extent_len(struct extent *extent)
{
	return extent->e_parent->de_len;
}

static void remove_extent(struct results_tree *res, struct extent *extent)
{
	struct dupe_extents *p = extent->e_parent;

again:
	p->de_score -= p->de_len;
	p->de_num_dupes--;

	list_del_init(&extent->e_list);
	list_del_init(&extent->e_file_extents);
	free(extent);

	if (p->de_num_dupes == 1) {
		/* It doesn't make sense to have one extent in a dup
		 * list. */
		if (list_empty(&p->de_extents))
			abort(); /* Another potential logic error */
		extent = list_entry(p->de_extents.next, struct extent, e_list);
		goto again;
	}

	if (p->de_num_dupes == 0) {
		rb_erase(&p->de_node, &res->root);
		free(p);
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
		if (pos == extent)
			abort();
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

void remove_overlapping_extents(struct results_tree *res,
				struct list_head *head)
{
	struct extent *orig;
	struct list_head *next;

	if (list_empty(head))
		return;

restart:
	next = head->next;
	while (next != head) {
		orig = list_entry(next, struct extent, e_file_extents);

		/*
		 * Re-start the search if we wound up deleting items -
		 * compare_extent could have deleted up to two items,
		 * either of which could be our loop cursor.
		 */
		if (compare_extent(res, orig, head))
			goto restart;

		next = next->next;
	}
}

void init_results_tree(struct results_tree *res)
{
	res->root = RB_ROOT;
	res->num_dupes = 0;
}
