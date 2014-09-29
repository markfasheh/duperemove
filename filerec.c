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

#include "kernel.h"
#include "rbtree.h"
#include "list.h"
#include "debug.h"

#include "filerec.h"

struct list_head filerec_list;
struct rb_root filerec_by_inum = RB_ROOT;
unsigned long long num_filerecs = 0ULL;

declare_alloc_tracking(filerec);
declare_alloc_tracking(filerec_token);

void init_filerec(void)
{
	INIT_LIST_HEAD(&filerec_list);
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

struct filerec_token *filerec_token_new(struct filerec *file)
{
	struct filerec_token *token = malloc_filerec_token();

	if (token) {
		rb_init_node(&token->t_node);
		token->t_file = file;
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

	if (find_filerec_token_rb(&file->comparisons, test))
		return 1;

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

	if (find_filerec_token_rb(&file->comparisons, test))
		return 0;

	t = filerec_token_new(test);
	if (!t)
		return ENOMEM;

	insert_filerec_token_rb(&file->comparisons, t);

	return 0;
}

static void free_compared_tree(struct filerec *file)
{
	struct rb_node *n = file->comparisons.rb_node;
	struct filerec_token *t;

	while (n) {
		t = rb_entry(n, struct filerec_token, t_node);
		n = rb_next(n);
		rb_erase(&t->t_node, &file->comparisons);
		filerec_token_free(t);
	}
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
		return -1;
	return 0;
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

static struct filerec *find_filerec(uint64_t inum, uint64_t subvolid)
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

static struct filerec *filerec_alloc_insert(const char *filename,
					    uint64_t inum, uint64_t subvolid)
{
	struct filerec *file = calloc_filerec(1);

	if (file) {
		file->filename = strdup(filename);
		if (!file->filename) {
			free_compared_tree(file);
			return NULL;
		}

		file->fd = -1;
		INIT_LIST_HEAD(&file->block_list);
		INIT_LIST_HEAD(&file->extent_list);
		INIT_LIST_HEAD(&file->tmp_list);
		rb_init_node(&file->inum_node);
		file->inum = inum;
		file->subvolid = subvolid;
		file->comparisons = RB_ROOT;

		insert_filerec(file);
		list_add_tail(&file->rec_list, &filerec_list);
		num_filerecs++;
	}
	return file;
}

struct filerec *filerec_new(const char *filename, uint64_t inum,
			    uint64_t subvolid)
{
	struct filerec *file = find_filerec(inum, subvolid);
	if (!file)
		file = filerec_alloc_insert(filename, inum, subvolid);
	return file;
}

void filerec_free(struct filerec *file)
{
	if (file) {
		filerec_close(file);

		free(file->filename);

		list_del(&file->block_list);
		list_del(&file->extent_list);
		list_del(&file->rec_list);
		list_del(&file->tmp_list);

		if (!RB_EMPTY_NODE(&file->inum_node))
			rb_erase(&file->inum_node, &filerec_by_inum);
		free_compared_tree(file);
		free_filerec(file);
		num_filerecs--;
	}
}

int filerec_open(struct filerec *file, int write)
{
	int fd, flags = O_RDONLY;

	if (write)
		flags = O_RDWR;

	if (file->fd == -1) {
		fd = open(file->filename, flags);
		if (fd == -1) {
			fprintf(stderr, "Error %d: %s while opening \"%s\" "
				"(write=%d)\n",
				errno, strerror(errno), file->filename, write);
			return errno;
		}

		file->fd = fd;
	}

	return 0;
}

void filerec_close(struct filerec *file)
{
	if (file->fd != -1) {
		close(file->fd);
		file->fd = -1;
	}
}

void filerec_close_files_list(struct list_head *open_files)
{
	struct filerec *file, *tmp;

	list_for_each_entry_safe(file, tmp, open_files, tmp_list) {
		list_del_init(&file->tmp_list);
		filerec_close(file);
	}
}

#define FIEMAP_BUF_SIZE	16384
#define FIEMAP_COUNT	((FIEMAP_BUF_SIZE - sizeof(struct fiemap)) / sizeof(struct fiemap_extent))
struct fiemap_ctxt {
	struct fiemap		*fiemap;
	char			buf[FIEMAP_BUF_SIZE];
	int			idx;
};

struct fiemap_ctxt *alloc_fiemap_ctxt(void)
{
	struct fiemap_ctxt *ctxt = malloc(sizeof(*ctxt));

	if (ctxt) {
		ctxt->fiemap = (struct fiemap *) ctxt->buf;
		ctxt->idx = -1;
	}
	return ctxt;
}

static inline int block_contained(uint64_t blkno,
				  struct fiemap_extent *extent)
{
	if (blkno >= extent->fe_logical &&
	    blkno < (extent->fe_logical + extent->fe_length))
		return 1;
	return 0;
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

int fiemap_iter_get_flags(struct fiemap_ctxt *ctxt, struct filerec *file,
			  uint64_t blkno, unsigned int *flags,
			  unsigned int *hole)
{
	int err;
	uint64_t new_start;
	struct fiemap *fiemap;
	struct fiemap_extent *extent;

	*flags = 0;
	*hole = 0;

	if (ctxt == NULL)
		return 0;
	/* we had a previous error or have no more extents to look up */
	if (ctxt->fiemap == NULL)
		return 0;

	fiemap = ctxt->fiemap;

	if (ctxt->idx == -1) {
		err = do_fiemap(fiemap, file, 0);
		if (err || fiemap->fm_mapped_extents == 0)
			goto out_last_map;

		ctxt->idx = 0;
	}

check:
	extent = &fiemap->fm_extents[ctxt->idx];
	if (block_contained(blkno, extent)) {
		*flags = extent->fe_flags;
		return 0;
	}

	/* blkno is in a hole, no need to move forward an extent yet */
	if (blkno < extent->fe_logical) {
		*hole = 1;
		return 0;
	}

	err = 0;
	/* No more extents for us to look for */
	if (extent->fe_flags & FIEMAP_EXTENT_LAST)
		goto out_last_map;

	ctxt->idx++;
	if (ctxt->idx == fiemap->fm_mapped_extents) {
		/* fiemap again to get more extents */
		new_start = extent->fe_logical + extent->fe_length;
		err = do_fiemap(fiemap, file, new_start);
		if (err ||  fiemap->fm_mapped_extents == 0)
			goto out_last_map;

		ctxt->idx = 0;
	}
	goto check;

out_last_map:
	ctxt->fiemap = NULL;
	return err;
}

/*
 * Skeleton for this function taken from e2fsprogs.git/misc/filefrag.c
 * which is Copyright 2003 by Theodore Ts'o and released under the GPL.
 */
int filerec_count_shared(struct filerec *file, uint64_t start, uint64_t len,
			 uint64_t *shared_bytes)
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
		dprintf("(fiemap) %s: start: %"PRIu64", len: %"PRIu64"\n",
			file->filename, start, len);

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
		rc = ioctl(file->fd, FS_IOC_FIEMAP, (unsigned long) fiemap);
		if (rc < 0)
			return errno;

		/* If 0 extents are returned, then more ioctls are not needed */
		if (fiemap->fm_mapped_extents == 0)
			break;

		for (i = 0; i < fiemap->fm_mapped_extents; i++) {
			if (fm_ext[i].fe_flags & FIEMAP_EXTENT_LAST)
				last = 1;

			dprintf("(fiemap) [%d] fe_logical: %llu, "
				"fe_length: %llu\n",
				i, (unsigned long long)fm_ext[i].fe_logical,
				(unsigned long long)fm_ext[i].fe_length);

			loff = fm_ext[i].fe_logical;
			ext_len = fm_ext[i].fe_length;
			ext_end = loff + ext_len;

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

			dprintf("(fiemap) loff: %"PRIu64" ext_len: %"PRIu64"\n",
				loff, ext_len);

			if (fm_ext[i].fe_flags & FIEMAP_EXTENT_SHARED)
				*shared_bytes += ext_len;
		}

		fiemap->fm_start = (fm_ext[i - 1].fe_logical +
				    fm_ext[i - 1].fe_length);
	} while (last == 0);

	return 0;
}

#ifdef FILEREC_TEST

int debug = 1;	/* Want prints from filerec_count_shared */

int main(int argc, char **argv)
{
	int ret;
	struct filerec *file;
	uint64_t loff, len;
	uint64_t shared = 0;

	init_filerec();

	/* test_filerec filename loff len */
	if (argc < 4) {
		printf("Usage: filerec_test filename loff len\n");
		return 1;
	}

	file = filerec_new(argv[1], 500, 1); /* Use made up ino */
	if (!file) {
		fprintf(stderr, "filerec_new(): malloc error\n");
		return 1;
	}

	ret = filerec_open(file, 0);
	if (ret)
		goto out;

	loff = atoll(argv[2]);
	len = atoll(argv[3]);

	ret = filerec_count_shared(file, loff, len, &shared);
	if (ret) {
		fprintf(stderr, "fiemap error %d: %s\n", ret, strerror(ret));
		goto out_close;
	}

	printf("%s: %"PRIu64" shared bytes\n", file->filename, shared);

out_close:
	filerec_close(file);
out:
	filerec_free(file);
	return ret;
}

#endif /* FILEREC_TEST */
