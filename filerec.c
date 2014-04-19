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

void init_filerec(void)
{
	INIT_LIST_HEAD(&filerec_list);
}

static void insert_filerec(struct filerec *file)
{
	struct rb_node **p = &filerec_by_inum.rb_node;
	struct rb_node *parent = NULL;
	struct filerec *tmp;

	while (*p) {
		parent = *p;

		tmp = rb_entry(parent, struct filerec, inum_node);

		if (file->inum < tmp->inum)
			p = &(*p)->rb_left;
		else if (file->inum > tmp->inum)
			p = &(*p)->rb_right;
		else
			abort(); /* We should never find a duplicate */
	}

	rb_link_node(&file->inum_node, parent, p);
	rb_insert_color(&file->inum_node, &filerec_by_inum);
	return;
}

static struct filerec *find_filerec(uint64_t inum)
{
	struct rb_node *n = filerec_by_inum.rb_node;
	struct filerec *file;

	while (n) {
		file = rb_entry(n, struct filerec, inum_node);

		if (inum < file->inum)
			n = n->rb_left;
		else if (inum > file->inum)
			n = n->rb_right;
		else
			return file;
	}
	return NULL;
}

static struct filerec *filerec_alloc_insert(const char *filename, uint64_t inum)
{
	struct filerec *file = calloc(1, sizeof(*file));

	if (file) {
		file->filename = strdup(filename);
		if (!file->filename) {
			free(file);
			return NULL;
		}

		file->fd = -1;
		INIT_LIST_HEAD(&file->block_list);
		INIT_LIST_HEAD(&file->extent_list);
		INIT_LIST_HEAD(&file->tmp_list);
		rb_init_node(&file->inum_node);
		file->inum = inum;

		insert_filerec(file);
		list_add_tail(&file->rec_list, &filerec_list);
	}
	return file;
}

struct filerec *filerec_new(const char *filename, uint64_t inum)
{
	struct filerec *file = find_filerec(inum);
	if (!file)
		file = filerec_alloc_insert(filename, inum);
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
		free(file);
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

	file = filerec_new(argv[1]);
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
