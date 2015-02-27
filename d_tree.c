/*
 * d_tree.c
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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include "csum.h"
#include "d_tree.h"
#include "debug.h"

struct d_tree *digest_new(unsigned char *digest)
{
	struct d_tree *token = malloc(sizeof(struct d_tree));

	if (token) {
		rb_init_node(&token->t_node);
		token->digest = malloc(sizeof(unsigned char) * digest_len);
		memcpy(token->digest, digest, digest_len);
	}
	return token;
}

int digest_insert(struct rb_root *root, struct d_tree *token)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct d_tree *tmp;
	int cmp;

 	while (*p) {
 		parent = *p;

 		tmp = rb_entry(parent, struct d_tree, t_node);

		cmp = memcmp(token->digest, tmp->digest, digest_len);
		if (cmp < 0)
			p = &(*p)->rb_left;
		else if (cmp > 0)
			p = &(*p)->rb_right;
		else {
			free(token->digest);
			free(token);
			return -1;
		}
	}

	rb_link_node(&token->t_node, parent, p);
	rb_insert_color(&token->t_node, root);
	return 0;
}

struct d_tree *digest_find(struct rb_root *root,
				unsigned char* digest)
{
	if (!root)
		return NULL;
	struct rb_node *n = root->rb_node;
	struct d_tree *t;
	int cmp;

	while (n) {
		t = rb_entry(n, struct d_tree, t_node);

		cmp = memcmp(digest, t->digest, digest_len);
		if (cmp < 0)
			n = n->rb_left;
		else if (cmp > 0)
			n = n->rb_right;
		else
			return t;
	}
	return NULL;
}

int digest_count(struct rb_root *root)
{
	struct rb_node *n = rb_first(root);
	int count;

	while (n) {
		count++;
		n = rb_next(n);
	}
	return(count);
}

void digest_free(struct rb_root *root)
{
	struct rb_node *n = rb_first(root);
	struct d_tree *t;

	while (n) {
		t = rb_entry(n, struct d_tree, t_node);
		n = rb_next(n);
		rb_erase(&t->t_node, root);
		free(t->digest);
		free(t);
	}

	abort_on(!RB_EMPTY_ROOT(root));
}
