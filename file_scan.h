#ifndef	__FILE_SCAN_H__
#define	__FILE_SCAN_H__

#include <sys/types.h>
#include "dbfile.h"

#include "list.h"
#include "csum.h"

/*
 * Returns nonzero on fatal errors only
 */
int add_file(const char *name, struct dbhandle *db);
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
dev_t fs_onefs_dev(void);
uint64_t fs_onefs_id(void);

int populate_tree(void (*callback)(void));

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

int add_exclude_pattern(const char *pattern);

#endif	/* __FILE_SCAN_H__ */
