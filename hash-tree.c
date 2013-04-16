#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "kernel.h"
#include "rbtree.h"
#include "list.h"

#include "csum.h"	/* for digest_len variable and DIGEST_LEN_MAX */

#include "hash-tree.h"

static void insert_block_list(struct hash_tree *tree,
			      struct dupe_blocks_list *list)
{
	struct rb_node **p = &tree->root.rb_node;
	struct rb_node *parent = NULL;
	struct dupe_blocks_list *tmp;
	int cmp;

	while (*p) {
		parent = *p;

		tmp = rb_entry(parent, struct dupe_blocks_list, dl_node);

		cmp = memcmp(list->dl_hash, tmp->dl_hash, digest_len);
		if (cmp < 0)
			p = &(*p)->rb_left;
		else if (cmp > 0)
			p = &(*p)->rb_right;
		else abort(); /* We should never find a duplicate */
	}

	rb_link_node(&list->dl_node, parent, p);
	rb_insert_color(&list->dl_node, &tree->root);

	tree->num_hashes++;
	return;
}

static struct dupe_blocks_list *find_block_list(struct hash_tree *tree,
					       unsigned char *digest)
{
	struct rb_node *n = tree->root.rb_node;
	struct dupe_blocks_list *list;
	int cmp;

	while (n) {
		list = rb_entry(n, struct dupe_blocks_list, dl_node);

		cmp = memcmp(digest, list->dl_hash, digest_len);
		if (cmp < 0)
			n = n->rb_left;
		else if (cmp > 0)
			n = n->rb_right;
		else return list;
	}
	return NULL;
}

struct file_block * insert_hashed_block(struct hash_tree *tree,
					unsigned char *digest,
					unsigned int fileid, uint64_t loff,
					struct list_head *head)
{
	struct file_block *e = malloc(sizeof(*e));
	struct dupe_blocks_list *d;

	if (!e)
		return NULL;

	d = find_block_list(tree, digest);
	if (d == NULL) {
		d = calloc(1, sizeof(*d));
		if (!d)
			return NULL;

		memcpy(d->dl_hash, digest, digest_len);
		rb_init_node(&d->dl_node);
		INIT_LIST_HEAD(&d->dl_list);

		insert_block_list(tree, d);
	}

	e->b_file = fileid;
	e->b_loff = loff;
	if (head)
		list_add_tail(&e->b_file_next, head);
	else
		INIT_LIST_HEAD(&e->b_file_next);
	e->b_parent = d;

	d->dl_num_elem++;
	list_add_tail(&e->b_list, &d->dl_list);

	tree->num_blocks++;
	return e;
}

void for_each_dupe(struct file_block *block, unsigned int fileid,
		  for_each_dupe_t func, void *priv)
{
	struct dupe_blocks_list *parent = block->b_parent;
	struct file_block *cur;

	list_for_each_entry(cur, &parent->dl_list, b_list) {
		/* Ignore self and any blocks from another fileid */
		if (cur == block)
			continue;

		if (cur->b_file != fileid)
			continue;

		if (func(cur, priv))
			break;
	}
}

static unsigned int seen_counter = 1;

int block_seen(struct file_block *block)
{
	return !!(block->b_seen == seen_counter);
}

void mark_block_seen(struct file_block *block)
{
	block->b_seen = seen_counter;
}

void clear_all_seen_blocks(void)
{
	seen_counter++;
}

void init_hash_tree(struct hash_tree *tree)
{
	tree->root = RB_ROOT;
	tree->num_blocks = tree->num_hashes = 0;
}
