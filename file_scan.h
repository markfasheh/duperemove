#ifndef	__FILE_SCAN_H__
#define	__FILE_SCAN_H__

#include "list.h"

/* from duperemove.c */
extern int run_dedupe;
extern int one_file_system;
extern int recurse_dirs;
extern unsigned int blocksize;
extern int do_lookup_extents;
extern unsigned int io_threads;
extern int skip_zeroes;
/*
 * Returns nonzero on fatal errors only
 */
int add_file(const char *name);
/*
 * Add from a db record. We still stat as before:
 *
 * If inum or subvolid do not match we mark the db record for
 * deletion. Otherwise we add a filerec based on the stat'd
 * information.
 *
 * * The filerec is marked to be updated in the db if size or mtime changed.
 * * The filerec is marked for rehash if mtime changed.
 */
int add_file_db(const char *filename, uint64_t inum, uint64_t subvolid,
		uint64_t size, uint64_t mtime, unsigned int seq, int *delete);

/* Set/get onefs state, info is gathered from our config table */
void fs_set_onefs(dev_t dev, uint64_t fsid);
dev_t fs_onefs_dev(void);
uint64_t fs_onefs_id(void);

struct dbfile_config;
int populate_tree(struct dbfile_config *cfg, unsigned int batch_size,
		void (*callback)(void));

/* For dbfile.c */
struct block_csum {
	uint64_t	loff;
	unsigned int	flags;
	unsigned char	digest[DIGEST_LEN];
};

struct extent_csum {
	uint64_t	loff;
	uint64_t	poff;
	uint64_t	len;
	unsigned int	flags;
	unsigned char	digest[DIGEST_LEN];
};

struct exclude_file {
	char *pattern;
	struct list_head list;
};

#endif	/* __FILE_SCAN_H__ */
