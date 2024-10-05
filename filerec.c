/*
 * filerec.c
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
 * Authors: Mark Fasheh <mfasheh@suse.de>
 */

#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "util.h"
#include "rbtree.h"
#include "debug.h"
#include "memstats.h"
#include "fiemap.h"

#include "filerec.h"

static GMutex filerec_fd_mutex;
struct filerec_list filerec_head = SLIST_HEAD_INITIALIZER(filerec_head);

static struct rb_root filerec_by_fileid = RB_ROOT;
unsigned long long num_filerecs = 0ULL;
unsigned int dedupe_seq = 0;

declare_alloc_tracking(filerec);
declare_alloc_tracking(filerec_token);

void init_filerec(void)
{
	SLIST_INIT(&filerec_head);
}

struct filerec_token *find_filerec_token_rb(struct rb_root *root,
					    struct filerec *val)
{
	struct rb_node *n = root->rb_node;
	struct filerec_token *t;

	while (n) {
		t = rb_entry(n, struct filerec_token, t_node);

		if (t->t_file > val)
			n = n->rb_left;
		else if (t->t_file < val)
			n = n->rb_right;
		else
			return t;
	}
	return NULL;
}

void insert_filerec_token_rb(struct rb_root *root,
			     struct filerec_token *token)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct filerec_token *tmp;

	while (*p) {
		parent = *p;

		tmp = rb_entry(parent, struct filerec_token, t_node);

		if (tmp->t_file > token->t_file)
			p = &(*p)->rb_left;
		else if (tmp->t_file < token->t_file)
			p = &(*p)->rb_right;
		else
			abort_lineno(); /* We should never find a duplicate */
	}

	rb_link_node(&token->t_node, parent, p);
	rb_insert_color(&token->t_node, root);
}

void filerec_token_free(struct filerec_token *token)
{
	if (token)
		free_filerec_token(token);
}

static void filerec_token_init(struct filerec_token *token,
			       struct filerec *file)
{
	rb_init_node(&token->t_node);
	token->t_file = file;
}

struct filerec_token *filerec_token_new(struct filerec *file)
{
	struct filerec_token *token = malloc_filerec_token();

	if (token) {
		filerec_token_init(token, file);
	}
	return token;
}

static int cmp_filerecs(struct filerec *file1, int64_t file2_fileid)
{
	if (file1->fileid < file2_fileid)
		return -1;
	else if (file1->fileid > file2_fileid)
		return 1;
	return 0;
}

static void insert_filerec(struct filerec *file)
{
	int c;
	struct rb_node **p = &filerec_by_fileid.rb_node;
	struct rb_node *parent = NULL;
	struct filerec *tmp;

	while (*p) {
		parent = *p;

		tmp = rb_entry(parent, struct filerec, fileid_node);

		c = cmp_filerecs(tmp, file->fileid);
		if (c < 0)
			p = &(*p)->rb_left;
		else if (c > 0)
			p = &(*p)->rb_right;
		else
			abort_lineno(); /* We should never find a duplicate */
	}

	rb_link_node(&file->fileid_node, parent, p);
	rb_insert_color(&file->fileid_node, &filerec_by_fileid);
	return;
}

struct filerec *filerec_find(int64_t fileid)
{
	int c;
	struct rb_node *n = filerec_by_fileid.rb_node;
	struct filerec *file;

	while (n) {
		file = rb_entry(n, struct filerec, fileid_node);

		c = cmp_filerecs(file, fileid);
		if (c < 0)
			n = n->rb_left;
		else if (c > 0)
			n = n->rb_right;
		else
			return file;
	}
	return NULL;
}

static struct filerec *filerec_alloc_insert(const char *filename,
					    int64_t fileid,
					    uint64_t size)
{
	struct filerec *file = calloc_filerec(1);

	if (!file)
		return NULL;

	file->filename = strdup(filename);
	if (!file->filename) {
		free_filerec(file);
		return NULL;
	}

	file->fd = -1;
	file->block_tree = RB_ROOT;
	rb_init_node(&file->fileid_node);
	file->fileid = fileid;
	file->size = size;

	insert_filerec(file);
	SLIST_INSERT_HEAD(&filerec_head, file, rec_list);
	num_filerecs++;

	return file;
}

struct filerec *filerec_new(const char *filename, int64_t fileid,
			    uint64_t size)
{
	struct filerec *file;
	file = filerec_alloc_insert(filename, fileid, size);
	return file;
}

static void filerec_free(struct filerec *file)
{
	if (file) {
		free(file->filename);

		/*
		 * XXX: Enable this check when we are freeing
		 * file_block's from free_all_filerecs()
		 */
//		abort_on(!RB_EMPTY_ROOT(&file->block_tree));
		SLIST_REMOVE(&filerec_head, file, filerec, rec_list);

		if (!RB_EMPTY_NODE(&file->fileid_node))
			rb_erase(&file->fileid_node, &filerec_by_fileid);
		free_filerec(file);
		num_filerecs--;
	}
}

void free_all_filerecs(void)
{
	struct filerec *file, *tmp;

	SLIST_FOREACH_SAFE(file, &filerec_head, rec_list, tmp) {
		filerec_free(file);
	}
}

/* Won't show error if file does not exist and quiet is true */
int filerec_open(struct filerec *file, bool quiet)
{
	int ret = 0;
	int fd;

	g_mutex_lock(&filerec_fd_mutex);
	if (file->fd_refs == 0) {
		abort_on(file->fd != -1);

		fd = open(file->filename, O_RDONLY);
		if (fd == -1) {
			ret = errno;
			if (ret != ENOENT || !quiet)
				eprintf("Error %d: %s while opening \"%s\"\n",
					ret, strerror(ret), file->filename);
			goto out_unlock;
		}

		file->fd = fd;
	}
	file->fd_refs++;
out_unlock:
	g_mutex_unlock(&filerec_fd_mutex);

	return ret;
}

void filerec_close(struct filerec *file)
{
	g_mutex_lock(&filerec_fd_mutex);
	abort_on(file->fd == -1);
	abort_on(file->fd_refs == 0);

	file->fd_refs--;

	if (file->fd_refs == 0) {
		close(file->fd);
		file->fd = -1;
	}
	g_mutex_unlock(&filerec_fd_mutex);
}

int filerec_open_once(struct filerec *file,
		      struct open_once *open_files)
{
	int ret;
	struct filerec_token *token;

	if (find_filerec_token_rb(&open_files->root, file))
		return 0;

	token = filerec_token_new(file);
	if (!token)
		return ENOMEM;

	ret = filerec_open(file, true);
	if (ret) {
		filerec_token_free(token);
		return ret;
	}

	insert_filerec_token_rb(&open_files->root, token);

	return 0;
}

void filerec_close_open_list(struct open_once *open_files)
{
	struct filerec_token *t;
	struct rb_node *n = rb_first(&open_files->root);

	while (n) {
		t = rb_entry(n, struct filerec_token, t_node);

		filerec_close(t->t_file);
		rb_erase(&t->t_node, &open_files->root);
		filerec_token_free(t);

		n = rb_first(&open_files->root);
	}
}

int fiemap_scan_extent(struct extent *extent)
{
	int ret = 0;
	_cleanup_(freep) struct fiemap *fiemap = NULL;
	struct fiemap_extent *result;

	ret = filerec_open(extent->e_file, true);
	if (ret)
		return ret;

	fiemap = do_fiemap(extent->e_file->fd);
	if (!fiemap) {
		filerec_close(extent->e_file);
		return -1;
	}

	result = get_extent(fiemap, extent->e_loff, NULL);
	if (!result) {
		filerec_close(extent->e_file);
		return -1;
	}

	extent->e_poff = result->fe_physical;
	filerec_close(extent->e_file);
	return ret;
}
