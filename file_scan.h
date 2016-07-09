#ifndef	__FILE_SCAN_H__
#define	__FILE_SCAN_H__

#include "d_tree.h"

/* from duperemove.c */
extern int run_dedupe;
extern int one_file_system;
extern int recurse_dirs;
extern unsigned int blocksize;
extern int do_lookup_extents;
extern unsigned int io_threads;
extern unsigned long long expected_hash_count;

/*
 * Returns nonzero on fatal errors only
 */
int add_file(const char *name, int dirfd);
int populate_tree();

/* For dbfile.c */
struct block {
	uint64_t	loff;
	unsigned int	flags;
	unsigned char	digest[DIGEST_LEN_MAX];
};

#endif	/* __FILE_SCAN_H__ */
