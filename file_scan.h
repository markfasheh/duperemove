#ifndef	__FILE_SCAN_H__
#define	__FILE_SCAN_H__

#include <sys/types.h>
#include "dbfile.h"

#include "list.h"
#include "csum.h"

#define MIN_BLOCKSIZE   (4U*1024)
/* max blocksize is somewhat arbitrary. */
#define MAX_BLOCKSIZE   (1024U*1024)
#define DEFAULT_BLOCKSIZE       (128U*1024)

/*
 * Returns nonzero on fatal errors only
 */
int scan_file(const char *name, struct dbhandle *db);

/* Set/get onefs state, info is gathered from our config table */
dev_t fs_onefs_dev(void);
uint64_t fs_onefs_id(void);

/* For dbfile.c */
struct block_csum {
	uint64_t	loff;
	unsigned char	digest[DIGEST_LEN];
};

struct extent_csum {
	uint64_t	loff;
	uint64_t	poff;
	uint64_t	len;
	unsigned char	digest[DIGEST_LEN];
};

struct exclude_file {
	char *pattern;
	struct list_head list;
};

struct file_to_scan {
	char *path;
	int fd;
	int64_t fileid;

	/*
	 * Used to record the current file position in the scan queue,
	 * to print the progress bar
	 */
	unsigned long long file_position;
};

int add_exclude_pattern(const char *pattern);

void filescan_prepare_pool();
void filescan_free_pool();

void add_file_fdupes(char *path);
#endif	/* __FILE_SCAN_H__ */
