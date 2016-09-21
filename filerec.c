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
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stddef.h>

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/fiemap.h>

#include <glib.h>

#include "kernel.h"
#include "rbtree.h"
#include "list.h"
#include "debug.h"
#include "memstats.h"

#include "filerec.h"

static GMutex filerec_fd_mutex;
struct list_head filerec_list;
static struct rb_root filerec_by_inum = RB_ROOT;
/* Name tree is secondary to inum tree */
static struct rb_root filerec_by_name = RB_ROOT;
unsigned long long num_filerecs = 0ULL;
unsigned int dedupe_seq = 0;

declare_alloc_tracking(filerec);
declare_alloc_tracking(filerec_token);

void init_filerec(void)
{
	INIT_LIST_HEAD(&filerec_list);
}

void debug_print_filerecs(void)
{
	struct filerec *file;

	list_for_each_entry(file, &filerec_list, rec_list) {
		printf("ino: %"PRIu64" subvol: %"PRIu64" blocks: %"PRIu64
		       " name: %s\n", file->inum, file->subvolid,
		       file->num_blocks, file->filename);
	}
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

int filerecs_compared(struct filerec *file1, struct filerec *file2)
{
	struct filerec *file = file1;
	struct filerec *test = file2;

	/*
	 * We can store only one pointer if we make a rule that we
	 * always search the filerec with the lower pointer value for
	 * the one with the higher pointer value.
	 */
	if (file1 > file2) {
		file = file2;
		test = file1;
	}

	g_mutex_lock(&file->tree_mutex);
	if (find_filerec_token_rb(&file->comparisons, test)) {
		g_mutex_unlock(&file->tree_mutex);
		return 1;
	}
	g_mutex_unlock(&file->tree_mutex);
	return 0;
}

int mark_filerecs_compared(struct filerec *file1, struct filerec *file2)
{
	struct filerec_token *t;
	struct filerec *file = file1;
	struct filerec *test = file2;

	if (file1 > file2) {
		file = file2;
		test = file1;
	}

	g_mutex_lock(&file->tree_mutex);
	if (find_filerec_token_rb(&file->comparisons, test)) {
		g_mutex_unlock(&file->tree_mutex);
		return 0;
	}
	g_mutex_unlock(&file->tree_mutex);

	t = filerec_token_new(test);
	if (!t)
		return ENOMEM;

	g_mutex_lock(&file->tree_mutex);
	if (find_filerec_token_rb(&file->comparisons, test)) {
		g_mutex_unlock(&file->tree_mutex);
		filerec_token_free(t);
		return 0;
	}

	insert_filerec_token_rb(&file->comparisons, t);
	g_mutex_unlock(&file->tree_mutex);

	return 0;
}

static void free_compared_tree(struct filerec *file)
{
	struct rb_node *n = rb_first(&file->comparisons);
	struct filerec_token *t;

	while (n) {
		t = rb_entry(n, struct filerec_token, t_node);
		n = rb_next(n);
		rb_erase(&t->t_node, &file->comparisons);
		filerec_token_free(t);
	}

	abort_on(!RB_EMPTY_ROOT(&file->comparisons));
}

void free_all_filerec_compared(void)
{
	struct filerec *file;

	list_for_each_entry(file, &filerec_list, rec_list)
		free_compared_tree(file);
}

static int cmp_filerecs(struct filerec *file1, uint64_t file2_inum,
			uint64_t file2_subvolid)
{
	if (file1->inum < file2_inum)
		return -1;
	else if (file1->inum > file2_inum)
		return 1;
	if (file1->subvolid < file2_subvolid)
		return -1;
	if (file1->subvolid > file2_subvolid)
		return 1;
	return 0;
}

static int cmp_filerecs_by_name(const char *filename1, const char *filename2)
{
	return strcmp(filename1, filename2);
}

static void insert_filerec(struct filerec *file)
{
	int c;
	struct rb_node **p = &filerec_by_inum.rb_node;
	struct rb_node *parent = NULL;
	struct filerec *tmp;

	while (*p) {
		parent = *p;

		tmp = rb_entry(parent, struct filerec, inum_node);

		c = cmp_filerecs(tmp, file->inum, file->subvolid);
		if (c < 0)
			p = &(*p)->rb_left;
		else if (c > 0)
			p = &(*p)->rb_right;
		else
			abort_lineno(); /* We should never find a duplicate */
	}

	rb_link_node(&file->inum_node, parent, p);
	rb_insert_color(&file->inum_node, &filerec_by_inum);
	return;
}

static void insert_filerec_by_name(struct filerec *file)
{
	int c;
	struct rb_node **p = &filerec_by_name.rb_node;
	struct rb_node *parent = NULL;
	struct filerec *tmp;

	while (*p) {
		parent = *p;

		tmp = rb_entry(parent, struct filerec, name_node);

		c = cmp_filerecs_by_name(file->filename, tmp->filename);
		if (c < 0)
			p = &(*p)->rb_left;
		else if (c > 0)
			p = &(*p)->rb_right;
		else
			abort_lineno(); /* We should never find a duplicate */
	}

	rb_link_node(&file->name_node, parent, p);
	rb_insert_color(&file->name_node, &filerec_by_name);
	return;
}

struct filerec *filerec_find(uint64_t inum, uint64_t subvolid)
{
	int c;
	struct rb_node *n = filerec_by_inum.rb_node;
	struct filerec *file;

	while (n) {
		file = rb_entry(n, struct filerec, inum_node);

		c = cmp_filerecs(file, inum, subvolid);
		if (c < 0)
			n = n->rb_left;
		else if (c > 0)
			n = n->rb_right;
		else
			return file;
	}
	return NULL;
}

struct filerec *filerec_find_by_name(const char *filename)
{
	int c;
	struct rb_node *n = filerec_by_name.rb_node;
	struct filerec *tmp;

	while (n) {
		tmp = rb_entry(n, struct filerec, name_node);

		c = cmp_filerecs_by_name(filename, tmp->filename);
		if (c < 0)
			n = n->rb_left;
		else if (c > 0)
			n = n->rb_right;
		else
			return tmp;
	}
	return NULL;
}

static struct filerec *filerec_alloc_insert(const char *filename,
					    uint64_t inum, uint64_t subvolid,
					    uint64_t size, uint64_t mtime)
{
	struct filerec *file = calloc_filerec(1);

	if (file) {
		file->filename = strdup(filename);
		if (!file->filename) {
			free_compared_tree(file);
			return NULL;
		}

		file->fd = -1;
		file->block_tree = RB_ROOT;
		INIT_LIST_HEAD(&file->tmp_list);
		rb_init_node(&file->inum_node);
		file->inum = inum;
		file->subvolid = subvolid;
		file->comparisons = RB_ROOT;
		file->size = size;
		file->mtime = mtime;
		g_mutex_init(&file->tree_mutex);

		insert_filerec(file);
		insert_filerec_by_name(file);
		list_add_tail(&file->rec_list, &filerec_list);
		num_filerecs++;
	}
	return file;
}

struct filerec *filerec_new(const char *filename, uint64_t inum,
			    uint64_t subvolid, uint64_t size, uint64_t mtime)
{
	struct filerec *file = filerec_find(inum, subvolid);
	if (!file)
		file = filerec_alloc_insert(filename, inum, subvolid, size,
					    mtime);
	return file;
}

void filerec_free(struct filerec *file)
{
	if (file) {
		free(file->filename);

		/*
		 * XXX: Enable this check when we are freeing
		 * file_block's from free_all_filerecs()
		 */
//		abort_on(!RB_EMPTY_ROOT(&file->block_tree));
		list_del(&file->rec_list);
		list_del(&file->tmp_list);

		if (!RB_EMPTY_NODE(&file->inum_node))
			rb_erase(&file->inum_node, &filerec_by_inum);
		if (!RB_EMPTY_NODE(&file->name_node))
			rb_erase(&file->name_node, &filerec_by_name);
		free_compared_tree(file);
		free_filerec(file);
		num_filerecs--;
	}
}

void free_all_filerecs(void)
{
	struct filerec *file, *tmp;

	list_for_each_entry_safe(file, tmp, &filerec_list, rec_list) {
		filerec_free(file);
	}
}

int filerec_open(struct filerec *file, int write)
{
	int ret = 0;
	int flags = O_RDONLY;
	int fd;

	if (write)
		flags = O_RDWR;

	g_mutex_lock(&filerec_fd_mutex);
	if (file->fd_refs == 0) {
		abort_on(file->fd != -1);

		fd = open(file->filename, flags);
		if (fd == -1) {
			ret = errno;
			fprintf(stderr, "Error %d: %s while opening \"%s\" "
				"(write=%d)\n",
				ret, strerror(ret), file->filename, write);
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

int filerec_open_once(struct filerec *file, int write,
		      struct open_once *open_files)
{
	int ret;
	struct filerec_token *token;

	if (find_filerec_token_rb(&open_files->root, file))
		return 0;

	token = filerec_token_new(file);
	if (!token)
		return ENOMEM;

	ret = filerec_open(file, write);
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

#define FIEMAP_BUF_SIZE	16384
#define FIEMAP_COUNT	((FIEMAP_BUF_SIZE - sizeof(struct fiemap)) / sizeof(struct fiemap_extent))
struct fiemap_ctxt {
	struct fiemap		*fiemap;
	char			buf[FIEMAP_BUF_SIZE];
	int			idx;

	unsigned int		last_flags;
	unsigned int		last_hole;
};

static inline void fc_set_last(struct fiemap_ctxt *fc, unsigned int flags,
				 unsigned int hole)
{
	fc->last_flags = flags;
	fc->last_hole = hole;
	fc->fiemap = NULL;
}

struct fiemap_ctxt *alloc_fiemap_ctxt(void)
{
	struct fiemap_ctxt *ctxt = malloc(sizeof(*ctxt));

	if (ctxt) {
		ctxt->fiemap = (struct fiemap *) ctxt->buf;
		ctxt->idx = -1;
		ctxt->last_flags = ctxt->last_hole = 0;
	}
	return ctxt;
}

static int do_fiemap(struct fiemap *fiemap, struct filerec *file,
		     uint64_t start)
{
	int err, i;
	struct fiemap_extent *extent;

	memset(fiemap, 0, sizeof(struct fiemap));

	fiemap->fm_length = ~0ULL;
	fiemap->fm_extent_count = FIEMAP_COUNT;
	fiemap->fm_start = start;

	dprintf("Fiemap file \"%s\", start: %"PRIu64", count: %u\n",
			file->filename, start, fiemap->fm_extent_count);

	err = ioctl(file->fd, FS_IOC_FIEMAP, (unsigned long) fiemap);
	if (err < 0)
		return errno;

	dprintf("%d extents found\n", fiemap->fm_mapped_extents);
	if (debug) {
		for (i = 0; i < fiemap->fm_mapped_extents; i++) {
			extent = &fiemap->fm_extents[i];

			dprintf("[%d] logical: %llu, length: %llu\n",
				i, (unsigned long long)extent->fe_logical,
				(unsigned long long)extent->fe_length);
		}
	}
	return 0;
}

/*
 * Assumes that we always call with blkno in ascending order
 */
int fiemap_iter_get_flags(struct fiemap_ctxt *ctxt, struct filerec *file,
			  uint64_t blkno, unsigned int *flags,
			  unsigned int *hole)
{
	int err;
	uint64_t fiestart = 0;
	struct fiemap *fiemap;
	struct fiemap_extent *extent;

	*flags = 0;
	*hole = 0;

	if (ctxt == NULL)
		return 0;
	/* we had a previous error or have no more extents to look up */
	if (ctxt->fiemap == NULL) {
		*hole = ctxt->last_hole;
		*flags = ctxt->last_flags;
		return 0;
	}

	fiemap = ctxt->fiemap;

	if (ctxt->idx == -1) {
		err = do_fiemap(fiemap, file, fiestart);
		if (err) {
			fc_set_last(ctxt, 0, 0);
			return err;
		}
		if (fiemap->fm_mapped_extents == 0) {
			*hole = 1;
			fc_set_last(ctxt, 0, 1);
			return 0;
		}
		ctxt->idx = 0;
	}

	/* Find first extent that ends past blkno */
	extent = &fiemap->fm_extents[ctxt->idx];
	while ((extent->fe_logical + extent->fe_length) <= blkno) {
		if (extent->fe_flags & FIEMAP_EXTENT_LAST)
			break;

		ctxt->idx++;

		if (ctxt->idx == fiemap->fm_mapped_extents) {
			fiestart = extent->fe_logical + extent->fe_length;
			err = do_fiemap(fiemap, file, fiestart);
			if (err) {
				fc_set_last(ctxt, 0, 0);
				return err;
			}
			if (fiemap->fm_mapped_extents == 0) {
				*hole = 1;
				fc_set_last(ctxt, 0, 1);
				return 0;
			}
			ctxt->idx = 0;
		}
		extent = &fiemap->fm_extents[ctxt->idx];
	}

	if (blkno < extent->fe_logical) {
		/*
		 * Extent starts after blkno. Don't have to worry
		 * about EXTENT_LAST here, we'll hit this extent on a
		 * future call.
		 */
		*hole = 1;
		return 0;
	}

	/*
	 * No more extents for us to look for
	 * Let's assume - that all following data is a hole
	 */
	if (extent->fe_flags & FIEMAP_EXTENT_LAST
	    && blkno >= (extent->fe_logical + extent->fe_length)) {
		*hole = 1;
		fc_set_last(ctxt, 0, 1);
		return 0;
	}

	*flags = extent->fe_flags;

	return 0;
}

#ifdef FILEREC_TEST
static char *fiemap_flags_str(unsigned long long flags);
#endif

/*
 * Skeleton for this function taken from e2fsprogs.git/misc/filefrag.c
 * which is Copyright 2003 by Theodore Ts'o and released under the GPL.
 */
int filerec_count_shared(struct filerec *file, uint64_t start, uint64_t len,
			 uint64_t *shared_bytes, uint64_t *poff,
			 uint64_t *first_plen)
{
	char buf[16384];
	struct fiemap *fiemap = (struct fiemap *)buf;
	struct fiemap_extent *fm_ext = &fiemap->fm_extents[0];
	int count = (sizeof(buf) - sizeof(*fiemap)) /
			sizeof(struct fiemap_extent);
	unsigned int i;
	int last = 0;
	int rc;
	uint64_t search_end = start + len;
	uint64_t loff, ext_len, ext_end;

	memset(fiemap, 0, sizeof(struct fiemap));

	do {
#ifndef	FILEREC_TEST
		dprintf("(fiemap) %s: start: %"PRIu64", len: %"PRIu64"\n",
			file->filename, start, len);
#endif

		/*
		 * Do search from 0 to EOF. btrfs was doing some weird
		 * stuff with mapped extent start values when I tried
		 * to search from user passed start to len. Instead
		 * the code can just catch extents outside our range
		 * in the for loop below and do the right thing.
		 *
		 * This issue can be revisited at some future point.
		 */
		fiemap->fm_length = ~0ULL;
		fiemap->fm_extent_count = count;
		fiemap->fm_start = start;
		rc = ioctl(file->fd, FS_IOC_FIEMAP, (unsigned long) fiemap);
		if (rc < 0)
			return errno;

		/* If 0 extents are returned, then more ioctls are not needed */
		if (fiemap->fm_mapped_extents == 0)
			break;

		if (poff)
			*poff = fiemap->fm_extents[0].fe_physical;

		for (i = 0; i < fiemap->fm_mapped_extents; i++) {
			if (fm_ext[i].fe_flags & FIEMAP_EXTENT_LAST)
				last = 1;
#ifndef FILEREC_TEST
			dprintf("(fiemap) [%u] fe_logical: %llu, "
				"fe_length: %llu, fe_physical: %llu, "
				"fe_flags: 0x%x\n",
				i, (unsigned long long)fm_ext[i].fe_logical,
				(unsigned long long)fm_ext[i].fe_length,
				(unsigned long long)fm_ext[i].fe_physical,
				fm_ext[i].fe_flags);
#else
			dprintf("(fiemap) [%u] fe_logical: %llu, "
				"fe_length: %llu, fe_physical: %llu, "
				"fe_flags: 0x%x %s\n",
				i, (unsigned long long)fm_ext[i].fe_logical,
				(unsigned long long)fm_ext[i].fe_length,
				(unsigned long long)fm_ext[i].fe_physical,
				fm_ext[i].fe_flags,
				fiemap_flags_str(fm_ext[i].fe_flags));
#endif

			loff = fm_ext[i].fe_logical;
			ext_len = fm_ext[i].fe_length;
			ext_end = loff + ext_len;

			if (first_plen) {
				*first_plen = ext_len;
				first_plen = NULL;/* Only return the first one */
			}

			if (ext_end <= start) {
				/* extent is before our search area */
				continue;
			}
			if (loff >= search_end) {
				/* extent starts after our search area */
				last = 1;
				i++; /* inc this so the math below works out */
				break;
			}

			/*
			 * First extent loff could begin before our
			 * search start. If so just shift our extent over.
			 */
			if (loff < start) {
				ext_len -= start - loff;
				loff = start;
			}
			/*
			 * Last extent could end past our intended
			 * range, trim length
			 */
			if (ext_end > search_end) {
				ext_len = search_end - loff;
				last = 1;
			}

//			dprintf("(fiemap) loff: %"PRIu64" ext_len: %"PRIu64
//				" flags: 0x%x\n",
//				loff, ext_len, fm_ext[i].fe_flags);

			if (!(fm_ext[i].fe_flags & FIEMAP_EXTENT_DELALLOC)
				&& fm_ext[i].fe_flags & FIEMAP_EXTENT_SHARED)
				*shared_bytes += ext_len;
		}

		start = (fm_ext[i - 1].fe_logical + fm_ext[i - 1].fe_length);
	} while (last == 0);

	return 0;
}

#ifdef FILEREC_TEST
#define	FLAG_STR_LEN	4096
static char flagstr[FLAG_STR_LEN];
/* This function is not thread-safe */
static char *fiemap_flags_str(unsigned long long flags)
{
	int size = FLAG_STR_LEN;
	int written = 0;
	char *str = flagstr;

	*str = '\0';

	if (flags) {
		written = snprintf(str, size, "(");
		str += written;
		size -= written;
	}

	if (flags & FIEMAP_EXTENT_LAST) {
		written = snprintf(str, size, "last ");
		str += written;
		size -= written;
	}

	if (flags & FIEMAP_EXTENT_UNKNOWN) {
		written = snprintf(str, size, "unknown ");
		str += written;
		size -= written;
	}
	if (flags & FIEMAP_EXTENT_DELALLOC) {
		written = snprintf(str, size, "delalloc ");
		str += written;
		size -= written;
	}
	if (flags & FIEMAP_EXTENT_ENCODED) {
		written = snprintf(str, size, "encoded ");
		str += written;
		size -= written;
	}
	if (flags & FIEMAP_EXTENT_DATA_ENCRYPTED) {
		written = snprintf(str, size, "data_encrypted ");
		str += written;
		size -= written;
	}
	if (flags & FIEMAP_EXTENT_NOT_ALIGNED) {
		written = snprintf(str, size, "not_aligned ");
		str += written;
		size -= written;
	}
	if (flags & FIEMAP_EXTENT_DATA_INLINE) {
		written = snprintf(str, size, "data_inline ");
		str += written;
		size -= written;
	}
	if (flags & FIEMAP_EXTENT_DATA_TAIL) {
		written = snprintf(str, size, "data_tail ");
		str += written;
		size -= written;
	}
	if (flags & FIEMAP_EXTENT_UNWRITTEN) {
		written = snprintf(str, size, "unwritten ");
		str += written;
		size -= written;
	}
	if (flags & FIEMAP_EXTENT_MERGED) {
		written = snprintf(str, size, "merged ");
		str += written;
		size -= written;
	}
	if (flags & FIEMAP_EXTENT_SHARED) {
		written = snprintf(str, size, "shared ");
		str += written;
		size -= written;
	}

	if (flags)
		snprintf(str, size, ")");

	return flagstr;
}

#ifdef	TEST_FIEMAP_ITER
static int get_size(struct filerec *file)
{
	int ret;
	struct stat st;

	ret = stat(file->filename, &st);
	if (ret == -1)
		return errno;

	file->size = st.st_size;
	return 0;
}

static int test_iter(struct filerec *file)
{
	int ret, bs = 128*1024;
	struct fiemap_ctxt *fc = alloc_fiemap_ctxt();
	unsigned int flags, hole;
	uint64_t blkno;

	debug = 1;	/* Want prints from filerec_count_shared */

	if (!fc)
		return ENOMEM;

	ret = get_size(file);
	if (ret)
		goto out;

	for(blkno = 0; blkno < file->size; blkno += bs) {
		ret = fiemap_iter_get_flags(fc, file, blkno, &flags, &hole);
		if (ret)
			return ret;

		printf("(test_iter) %s: block: %"PRIu64" hole: %d flags: %s\n",
		       file->filename, blkno, hole, fiemap_flags_str(flags));
	}

out:
	free(fc);
	return ret;
}
#endif	/* TEST_FIEMAP_ITER */

int main(int argc, char **argv)
{
	int ret, i;
	struct filerec *file;
	uint64_t shared;

	init_filerec();

	if (argc < 2) {
		printf("Usage: show_shared_extents filename1 filename2 ...\n");
		return 1;
	}

	for (i = 1; i < argc; i++) {
		file = filerec_new(argv[i], 500 + i, 1, 0, 0);
		if (!file) {
			fprintf(stderr, "filerec_new(): malloc error\n");
			return 1;
		}

		ret = filerec_open(file, 0);
		if (ret)
			goto out;

#ifdef	TEST_FIEMAP_ITER
		test_iter(file);
#else

		shared = 0;
		ret = filerec_count_shared(file, 0, -1ULL, &shared, NULL, NULL);
		filerec_close(file);
		if (ret) {
			fprintf(stderr, "fiemap error %d: %s\n", ret, strerror(ret));
			goto out;
		}

		printf("%s: %"PRIu64" shared bytes\n", file->filename, shared);
#endif
		filerec_free(file);
		file = NULL;
	}

out:
	filerec_free(file);
	return ret;
}

#endif /* FILEREC_TEST */
