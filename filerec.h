#ifndef __FILEREC__
#define __FILEREC__

#include "list.h"

extern struct list_head filerec_list;

struct filerec {
	int		fd;			/* file descriptor */
	char	*filename;		/* path to file */

	struct list_head	block_list;	/* head for hash
						 * blocks node list */
	struct list_head	extent_list;	/* head for results node list */

	struct list_head	rec_list;	/* all filerecs */
};

static inline void init_filerec(void)
{
	INIT_LIST_HEAD(&filerec_list);
}

struct filerec *filerec_new(const char *filename);
void filerec_free(struct filerec *file);
int filerec_open(struct filerec *file, int write);
void filerec_close(struct filerec *file);

#endif /* __FILEREC__ */
