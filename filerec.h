#ifndef __FILEREC__
#define __FILEREC__

#include <stdint.h>
#include "rbtree.h"
#include "list.h"

extern struct list_head filerec_list;

struct filerec {
	int		fd;			/* file descriptor */
	char	*filename;		/* path to file */

	uint64_t		inum;
	struct rb_node		inum_node;

	struct list_head	block_list;	/* head for hash
						 * blocks node list */
	struct list_head	extent_list;	/* head for results node list */

	struct list_head	rec_list;	/* all filerecs */

	struct list_head	tmp_list;
};

void init_filerec(void);

struct filerec *filerec_new(const char *filename, uint64_t inum);
void filerec_free(struct filerec *file);
int filerec_open(struct filerec *file, int write);
void filerec_close(struct filerec *file);

void filerec_close_files_list(struct list_head *open_files);

int filerec_count_shared(struct filerec *file, uint64_t start, uint64_t len,
			 uint64_t *shared_bytes);

#endif /* __FILEREC__ */
