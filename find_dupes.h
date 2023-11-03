#ifndef	__FIND_DUPES_H__
#define	__FIND_DUPES_H__

#include "opt.h"

/* from duperemove.c */
extern unsigned int blocksize;

int find_additional_dedupe(struct results_tree *extents);

#endif	/* __FIND_DUPES_H__ */
