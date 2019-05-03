#ifndef	__DBFILE_H__
#define	__DBFILE_H__

#include <sqlite3.h>
struct filerec;
struct block_csum;
struct extent_csum;
struct results_tree;
struct dbfile_config;

#define DB_FILE_MAJOR	3
#define DB_FILE_MINOR	0
#define BLOCK_DEDUPE_DBFILE_VER	2

int dbfile_create(char *filename, int *dbfile_is_new, int requested_version,
		  struct dbfile_config *cfg);
int dbfile_open(char *filename, struct dbfile_config *cfg);
void dbfile_close(void);

struct sqlite3 *dbfile_open_handle(char *filename);
void dbfile_close_handle(struct sqlite3 *db);

struct dbfile_config {
	unsigned int	blocksize;
	uint64_t	num_hashes;
	uint64_t	num_files;
	dev_t		onefs_dev;
	uint64_t	onefs_fsid;
	int		major;
	int		minor;
	char		hash_type[8];
	unsigned int	dedupe_seq;
#define EXTENT_HASH_SRC_DIGEST	0
#define EXTENT_HASH_SRC_DATA	1
	unsigned int	extent_hash_src;
};
int dbfile_get_config(sqlite3 *db, struct dbfile_config *cfg);
int dbfile_sync_config(struct dbfile_config *cfg);

struct hash_tree;
struct hash_file_header;
struct rb_root;

int create_indexes(sqlite3 *db, struct dbfile_config *cfg);

/*
 * Load hashes into hash_tree only if they have a duplicate in the db.
 * The extent search is later run on the resulting hash_tree.
 */
int dbfile_load_block_hashes(struct hash_tree *hash_tree);
int dbfile_load_extent_hashes(struct results_tree *res);

struct file_extent {
	uint64_t	poff;
	uint64_t	loff;
	uint64_t	len;
	unsigned int	flags;
};
int dbfile_load_nondupe_file_extents(sqlite3 *db, struct filerec *file,
				     struct file_extent **ret_extents,
				     unsigned int *num_extents);
int dbfile_load_one_file_extent(sqlite3 *db, struct filerec *file,
				uint64_t loff, unsigned int len,
				struct file_extent *extent);

/* Scan files based on db contents. Removes any orphaned file records. */
int dbfile_scan_files(struct dbfile_config *cfg);

/* Write any filerecs marked as needing update to the db */
int dbfile_sync_files(sqlite3 *db);

/*
 * Following are used during file scan stage to get our hashes into
 * the database.
 */
sqlite3 *dbfile_get_handle(void);
int dbfile_store_file_info(sqlite3 *db, struct filerec *file);
int dbfile_store_block_hashes(sqlite3 *db, struct dbfile_config *cfg,
			      struct filerec *file, uint64_t nb_hash,
			      struct block_csum *hashes);
int dbfile_store_extent_hashes(sqlite3 *db, struct dbfile_config *cfg,
			       struct filerec *file, uint64_t nb_hash,
			       struct extent_csum *hashes);
int dbfile_begin_trans(sqlite3 *db);
int dbfile_commit_trans(sqlite3 *db);

/*
 * This is used for printing so we can get away with chars from sqlite
 * for now.
 */
typedef void (*iter_files_func)(char *filename, char *ino, char *subvol);
int dbfile_iter_files(sqlite3 *db, iter_files_func func);

int dbfile_remove_file(sqlite3 *db, struct dbfile_config *cfg,
		       const char *filename);

#endif	/* __DBFILE_H__ */
