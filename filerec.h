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
#include <time.h>
#include <glib.h>
#include "rbtree.h"
#include "list.h"
#include "results-tree.h"

extern struct list_head filerec_list;
extern unsigned long long num_filerecs;
extern unsigned int dedupe_seq; /* This is incremented on every dedupe pass */

struct filerec {
	int		fd;			/* file descriptor */
	unsigned int	fd_refs;			/* fd refcount */

	char	*filename;		/* path to file */
	uint64_t subvolid;

	uint64_t		inum;
	struct rb_node		inum_node;

	uint64_t		size;
	struct rb_root		block_tree;	/* root for hash blocks tree */

	struct list_head	rec_list;	/* all filerecs */
};

void init_filerec(void);
void free_all_filerecs(void);

struct filerec *filerec_new(const char *filename, uint64_t inum,
			    uint64_t subvolid, uint64_t size);
struct filerec *filerec_find(uint64_t inum, uint64_t subvolid);

void filerec_free(struct filerec *file);
int filerec_open(struct filerec *file, bool quiet);
void filerec_close(struct filerec *file);

struct open_once {
	struct rb_root	root;
};
#define	OPEN_ONCE_INIT	(struct open_once) { RB_ROOT, }
#define OPEN_ONCE(name)	struct open_once name = OPEN_ONCE_INIT

int filerec_open_once(struct filerec *file,
		      struct open_once *open_files);
void filerec_close_open_list(struct open_once *open_files);

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

struct fiemap_ctxt;
struct fiemap_ctxt *alloc_fiemap_ctxt(void);
int fiemap_iter_next_extent(struct fiemap_ctxt *ctxt, int fd,
			    uint64_t *poff, uint64_t *loff, uint64_t *len,
			    unsigned int *flags);
int filerec_count_shared(struct filerec *file, uint64_t loff, uint32_t len,
			 uint64_t *shared);

#define	NANOSECONDS	1000000000
static inline uint64_t timespec_to_nano(struct timespec *t)
{
	return (uint64_t)t->tv_nsec + t->tv_sec * NANOSECONDS;
}

int fiemap_scan_extent(struct extent *extent);
#endif /* __FILEREC__ */
