/*
 * filerec.h
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
 */

#ifndef __FILEREC__
#define __FILEREC__

#include <stdint.h>
#include "rbtree.h"
#include "list.h"

extern struct list_head filerec_list;
extern unsigned long long num_filerecs;

struct filerec {
	int		fd;			/* file descriptor */
	unsigned int	fd_refs;			/* fd refcount */
	char	*filename;		/* path to file */
	uint64_t subvolid;

	uint64_t		inum;
	struct rb_node		inum_node;

	uint64_t		num_blocks;	/* blocks we've inserted */
	uint64_t		size;
	struct rb_root		block_tree;	/* root for hash blocks tree */
	struct list_head	extent_list;	/* head for results node list */

	struct list_head	rec_list;	/* all filerecs */

	struct list_head	tmp_list;

	struct rb_root		comparisons;
};

void init_filerec(void);
void free_all_filerecs(void);
void debug_print_filerecs(void);

struct filerec *filerec_new(const char *filename, uint64_t inum,
			    uint64_t subvolid, uint64_t size);
struct filerec *filerec_find(uint64_t inum, uint64_t subvolid);
void filerec_free(struct filerec *file);
int filerec_open(struct filerec *file, int write);
void filerec_close(struct filerec *file);

struct open_once {
	struct rb_root	root;
};
#define	OPEN_ONCE_INIT	(struct open_once) { RB_ROOT, }
#define OPEN_ONCE(name)	struct open_once name = OPEN_ONCE_INIT

int filerec_open_once(struct filerec *file, int write,
		      struct open_once *open_files);
void filerec_close_open_list(struct open_once *open_files);

int filerec_count_shared(struct filerec *file, uint64_t start, uint64_t len,
			 uint64_t *shared_bytes, uint64_t *poff,
			 uint64_t *first_plen);

/*
 * Track unique filerecs in a tree. Two places in the code use this:
 *	- filerec comparison tracking in filerec.c
 *	- conversion of large dupe lists in hash-tree.c
 * User has to define an rb_root, and a "free all" function.
 */
struct filerec_token {
	struct filerec	*t_file;
	struct rb_node	t_node;
};
struct filerec_token *find_filerec_token_rb(struct rb_root *root,
					    struct filerec *val);
void insert_filerec_token_rb(struct rb_root *root,
			     struct filerec_token *token);
void filerec_token_free(struct filerec_token *token);
struct filerec_token *filerec_token_new(struct filerec *file);

int filerecs_compared(struct filerec *file1, struct filerec *file2);
int mark_filerecs_compared(struct filerec *file1, struct filerec *file2);


struct fiemap_ctxt;
struct fiemap_ctxt *alloc_fiemap_ctxt(void);
void fiemap_ctxt_init(struct fiemap_ctxt *ctxt);
int fiemap_iter_get_flags(struct fiemap_ctxt *ctxt, struct filerec *file,
			  uint64_t blkno, unsigned int *flags,
			  unsigned int *hole);
#endif /* __FILEREC__ */
