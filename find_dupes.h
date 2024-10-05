#ifndef	__FIND_DUPES_H__
#define	__FIND_DUPES_H__

#include "opt.h"
#include "results-tree.h"

/* from duperemove.c */
extern unsigned int blocksize;

int find_additional_dedupe(struct results_tree *extents);

void extents_search_init(void);
void extents_search_free(void);
#endif	/* __FIND_DUPES_H__ */
