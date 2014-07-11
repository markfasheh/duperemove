/*
 * hash-tree.c
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
#include "debug.h"

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

int insert_hashed_block(struct hash_tree *tree,	struct hash_tree *extents, 
			unsigned char *digest, unsigned char *edigest,
			struct filerec *file, uint64_t loff)
{
	struct file_block *e = malloc(sizeof(*e));
	struct dupe_blocks_list *d;
	struct dupe_blocks_list *c;
	int already_deduped = 0;

	if (!e)
		return ENOMEM;
	
	if (edigest != NULL) {
		c = find_block_list(extents, edigest);
		if (c == NULL) {
			c = calloc(1, sizeof(*d));
			if (!c) {
				free(e);
				return ENOMEM;
			}
			
			memcpy(c->dl_hash, edigest, digest_len);
			rb_init_node(&c->dl_node);
			INIT_LIST_HEAD(&c->dl_list);
			
			insert_block_list(extents, c);
		} else {
			already_deduped = 1;
		}
	}

	d = find_block_list(tree, digest);
	if (d == NULL) {
		abort_on(already_deduped); /* can't be already deduped if
					    * we never saw it before */
		
		d = calloc(1, sizeof(*d));
		if (!d) {
			free(e);
			return ENOMEM;
		}

		memcpy(d->dl_hash, digest, digest_len);
		rb_init_node(&d->dl_node);
		INIT_LIST_HEAD(&d->dl_list);

		insert_block_list(tree, d);
	}

	e->b_file = file;
	e->b_seen = 0;
	e->b_loff = loff;
	list_add_tail(&e->b_file_next, &file->block_list);
	e->b_parent = d;
	e->b_sharing = c;
	
	if (!already_deduped) {
		d->dl_num_elem++;
		list_add_tail(&e->b_list, &d->dl_list);
		tree->num_blocks++;
	}
	
	c->dl_num_elem++;
	list_add_tail(&e->b_extents, &c->dl_list);
	extents->num_blocks++;
	
	return 0;
}

static void remove_hashed_block(struct hash_tree *tree,
				struct file_block *block)
{
	struct dupe_blocks_list *blocklist = block->b_parent;

	if (blocklist->dl_num_elem == 0)
		abort();

	list_del(&block->b_file_next);
	list_del(&block->b_list);

	blocklist->dl_num_elem--;
	if (blocklist->dl_num_elem == 0) {
		rb_erase(&blocklist->dl_node, &tree->root);
		tree->num_hashes--;

		free(blocklist);
	}

	free(block);
	tree->num_blocks--;
}

void remove_hashed_blocks(struct hash_tree *tree, struct filerec *file)
{
	struct file_block *block, *tmp;

	list_for_each_entry_safe(block, tmp, &file->block_list, b_file_next)
		remove_hashed_block(tree, block);
}

void for_each_dupe(struct file_block *block, struct filerec *file,
		   for_each_dupe_t func, void *priv)
{
	struct dupe_blocks_list *parent = block->b_parent;
	struct file_block *cur;

	list_for_each_entry(cur, &parent->dl_list, b_list) {
		/* Ignore self and any blocks from another file */
		if (cur == block)
			continue;

		if (cur->b_file != file)
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

int block_ever_seen(struct file_block *block)
{
	return !(block->b_seen == 0);
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
