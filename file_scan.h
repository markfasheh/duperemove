#ifndef	__FILE_SCAN_H__
#define	__FILE_SCAN_H__

/* from duperemove.c */
extern int run_dedupe;
extern int one_file_system;
extern int recurse_dirs;
extern unsigned int blocksize;
extern int do_lookup_extents;
extern unsigned int hash_threads;

/*
 * Returns nonzero on fatal errors only
 */
int add_file(const char *name, int dirfd);
int populate_hash_tree(struct hash_tree *tree);

#endif	/* __FILE_SCAN_H__ */
