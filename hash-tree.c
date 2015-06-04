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

#include <stdio.h>
#include <inttypes.h>

#include "kernel.h"
#include "rbtree.h"
#include "list.h"

#include "csum.h"	/* for digest_len variable and DIGEST_LEN_MAX */
#include "filerec.h"

#include "hash-tree.h"
#include "debug.h"
#include "memstats.h"

declare_alloc_tracking(file_block);
declare_alloc_tracking(dupe_blocks_list);

extern unsigned int blocksize;

/*
 * Management of filerec->block_tree rb tree. This is simple - ordered
 * by loff. So that the code in find_dupes.c can walk them in logical
 * order. We use a tree for this so that our dbfile backend is free to
 * insert blocks in any order. There's no other tree management
 * required than insert.
 */
static void insert_block_into_filerec(struct filerec *file,
				      struct file_block *block)
{
	struct rb_node **p = &file->block_tree.rb_node;
	struct rb_node *parent = NULL;
	struct file_block *tmp;

	while (*p) {
		parent = *p;

		tmp = rb_entry(parent, struct file_block, b_file_next);

		if (tmp->b_loff > block->b_loff)
			p = &(*p)->rb_left;
		else if (tmp->b_loff < block->b_loff)
			p = &(*p)->rb_right;
		else abort_lineno(); /* If need be, insert_hashed_block() should
				      * check for this (right now it doesn't) */
	}

	rb_link_node(&block->b_file_next, parent, p);
	rb_insert_color(&block->b_file_next, &file->block_tree);
}

void debug_print_block(struct file_block *e)
{
	struct filerec *f = e->b_file;

	printf("%s\tloff: %llu lblock: %llu seen: %u flags: 0x%x\n",
	       f->filename,
	       (unsigned long long)e->b_loff,
	       (unsigned long long)e->b_loff / blocksize, e->b_seen,
	       e->b_flags);
}

void debug_print_hash_tree(struct hash_tree *tree)
{
	struct rb_root *root = &tree->root;
	struct rb_node *node = rb_first(root);
	struct dupe_blocks_list *dups;
	struct file_block *block;
	struct list_head *p;

	if (!debug)
		return;

	dprintf("Block hash tree has %"PRIu64" hash nodes and %"PRIu64" block items\n",
		tree->num_hashes, tree->num_blocks);

	while (1) {
		if (node == NULL)
			break;

		dups = rb_entry(node, struct dupe_blocks_list, dl_node);

		dprintf("All blocks with hash: ");
		debug_print_digest(stdout, dups->dl_hash);
		dprintf("\n");

		list_for_each(p, &dups->dl_list) {
			block = list_entry(p, struct file_block, b_list);
			debug_print_block(block);
		}
		node = rb_next(node);
	}
}

struct file_hash_head *find_file_hash_head(struct dupe_blocks_list *dups,
					   struct filerec *file)
{
	struct rb_node *n = dups->dl_files_root.rb_node;
	struct file_hash_head *head;

	while (n) {
		head = rb_entry(n, struct file_hash_head, h_node);

		if (head->h_file < file)
			n = n->rb_left;
		else if (head->h_file > file)
			n = n->rb_right;
		else return head;
	}
	return NULL;
}

static void insert_file_hash_head(struct dupe_blocks_list *dups,
				  struct file_hash_head *head)
{
	struct rb_node **p = &dups->dl_files_root.rb_node;
	struct rb_node *parent = NULL;
	struct file_hash_head *tmp;

	while (*p) {
		parent = *p;

		tmp = rb_entry(parent, struct file_hash_head, h_node);

		if (tmp->h_file < head->h_file)
			p = &(*p)->rb_left;
		else if (tmp->h_file > head->h_file)
			p = &(*p)->rb_right;
		else abort_lineno(); /* We should never find a duplicate */
	}

	rb_link_node(&head->h_node, parent, p);
	rb_insert_color(&head->h_node, &dups->dl_files_root);
}

static int add_file_hash_head(struct dupe_blocks_list *dups,
			      struct file_block *block)
{
	struct filerec *file = block->b_file;
	struct file_hash_head *head = find_file_hash_head(dups, file);

	if (head)
		goto add;

	head = malloc(sizeof(*head));
	if (!head)
		return ENOMEM;

	head->h_file = file;
	rb_init_node(&head->h_node);
	INIT_LIST_HEAD(&head->h_blocks);
	insert_file_hash_head(dups, head);
	dups->dl_num_files++;
add:
	/* We depend on this being added in increasing block order */
	list_add_tail(&block->b_head_list, &head->h_blocks);
	return 0;
}

static void free_one_hash_head(struct dupe_blocks_list *dups,
			       struct file_hash_head *head)
{
	rb_erase(&head->h_node, &dups->dl_files_root);
	free(head);
}

int file_in_dups_list(struct dupe_blocks_list *dups, struct filerec *file)
{
	if (find_file_hash_head(dups, file))
		return 1;
	return 0;
}

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
		else abort_lineno(); /* We should never find a duplicate */
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

int insert_hashed_block(struct hash_tree *tree,	unsigned char *digest,
			struct filerec *file, uint64_t loff, unsigned int flags)
{
	struct file_block *e = malloc_file_block();
	struct dupe_blocks_list *d;

	if (!e)
		return ENOMEM;

	abort_on((flags & FILE_BLOCK_PARTIAL) && !(file->size % blocksize));

	d = find_block_list(tree, digest);
	if (d == NULL) {
		d = calloc_dupe_blocks_list(1);
		if (!d) {
			free_file_block(e);
			return ENOMEM;
		}

		memcpy(d->dl_hash, digest, digest_len);
		rb_init_node(&d->dl_node);
		rb_init_node(&d->dl_by_size);
		INIT_LIST_HEAD(&d->dl_list);
		d->dl_files_root = RB_ROOT;

		insert_block_list(tree, d);
	}

	e->b_file = file;
	e->b_seen = 0;
	e->b_loff = loff;
	e->b_flags = flags;
	e->b_parent = d;

	rb_init_node(&e->b_file_next);
	INIT_LIST_HEAD(&e->b_head_list);

	if (add_file_hash_head(d, e)) {
		free_file_block(e);
		return ENOMEM;
	}

	insert_block_into_filerec(file, e);
	file->num_blocks++;

	d->dl_num_elem++;
	list_add_tail(&e->b_list, &d->dl_list);

	tree->num_blocks++;
	return 0;
}

static void remove_hashed_block(struct hash_tree *tree,
				struct file_block *block, struct filerec *file)
{
	struct dupe_blocks_list *blocklist = block->b_parent;
	struct file_hash_head *head;

	abort_on(blocklist->dl_num_elem == 0);

	if (!RB_EMPTY_NODE(&block->b_file_next)) {
		abort_on(file->num_blocks == 0);
		file->num_blocks--;
	}

	rb_erase(&block->b_file_next, &file->block_tree);
	list_del(&block->b_list);

	list_del(&block->b_head_list);
	head = find_file_hash_head(blocklist, file);
	if (head && list_empty(&head->h_blocks))
		free_one_hash_head(blocklist, head);

	blocklist->dl_num_elem--;
	if (blocklist->dl_num_elem == 0) {
		rb_erase(&blocklist->dl_node, &tree->root);
		tree->num_hashes--;

		free_dupe_blocks_list(blocklist);
	}

	free_file_block(block);
	tree->num_blocks--;
}

void remove_hashed_blocks(struct hash_tree *tree, struct filerec *file)
{
	struct rb_node *node;
	struct file_block *block;

	while ((node = rb_first(&file->block_tree)) != NULL) {
		block = rb_entry(node, struct file_block, b_file_next);
		remove_hashed_block(tree, block, file);
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
