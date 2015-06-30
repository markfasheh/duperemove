#ifndef	__FIND_DUPES_H__
#define	__FIND_DUPES_H__

/* from duperemove.c */
extern int stdout_is_tty;
extern int do_lookup_extents;
extern unsigned int blocksize;

int find_all_dupes(struct hash_tree *tree, struct results_tree *res);

#endif	/* __FIND_DUPES_H__ */
