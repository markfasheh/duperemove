#ifndef	__DBFILE_H__
#define	__DBFILE_H__

#include <stdlib.h>
#include <stdint.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <sys/types.h>
#include <uuid/uuid.h>

#include "util.h"
#include "csum.h"
#include "threads.h"

struct filerec;
struct block_csum;
struct extent_csum;
struct results_tree;
struct dbfile_config;

#define DB_FILE_MAJOR	4
#define DB_FILE_MINOR	1

struct stmts {
	sqlite3_stmt *insert_block;
	sqlite3_stmt *insert_extent;
	sqlite3_stmt *update_scanned_file;
	sqlite3_stmt *find_blocks;
	sqlite3_stmt *find_top_b_hashes;
	sqlite3_stmt *find_top_e_hashes;
	sqlite3_stmt *find_b_files_count;
	sqlite3_stmt *find_e_files_count;
	sqlite3_stmt *update_extent_poff;
	sqlite3_stmt *write_file;
	sqlite3_stmt *remove_block_hashes;
	sqlite3_stmt *remove_extent_hashes;
	sqlite3_stmt *load_filerec;
	sqlite3_stmt *get_duplicate_blocks;
	sqlite3_stmt *get_duplicate_extents;
	sqlite3_stmt *get_duplicate_files;
	sqlite3_stmt *get_file_extent;
	sqlite3_stmt *get_nondupe_extents;
	sqlite3_stmt *delete_file;
	sqlite3_stmt *select_file_changes;
	sqlite3_stmt *count_b_hashes;
	sqlite3_stmt *count_e_hashes;
	sqlite3_stmt *count_files;
	sqlite3_stmt *get_max_dedupe_seq;
	sqlite3_stmt *delete_unscanned_files;
	sqlite3_stmt *rename_file;
};

struct dbhandle {
	sqlite3 *db;
	struct stmts stmts;
};

struct file {
	int64_t		id;
	char		filename[PATH_MAX + 1];
	uint64_t	ino;
	uint64_t	subvol;
	size_t		size;
	uint64_t	blocks;
	uint64_t	mtime;
	unsigned int	dedupe_seq;
	char		digest[DIGEST_LEN];
	unsigned int	flags;
};

struct dbhandle *dbfile_open_handle(char *filename);
void dbfile_close_handle(struct dbhandle *db);

/*
 * Open the database
 * On success, the handle is registered to be freed when the thread pool is freed
 */
struct dbhandle *dbfile_open_handle_thread(char *filename, struct threads_pool *pool);

void dbfile_lock(void);
void dbfile_unlock(void);

struct dbfile_config {
	unsigned int	blocksize;
	int		major;
	int		minor;
	char		hash_type[8];
	unsigned int	dedupe_seq;
	uuid_t		fs_uuid;
};
int dbfile_get_config(sqlite3 *db, struct dbfile_config *cfg);
int __dbfile_sync_config(sqlite3 *db, struct dbfile_config *cfg);
int dbfile_sync_config(struct dbhandle *db, struct dbfile_config *cfg);

struct dbfile_stats {
	uint64_t	num_b_hashes;
	uint64_t	num_e_hashes;
	uint64_t	num_files;
};
int dbfile_get_stats(struct dbhandle *db, struct dbfile_stats *stats);

uint64_t count_file_by_digest(struct dbhandle *db, unsigned char *digest,
				bool show_block_hashes);

struct hash_tree;

/*
 * Load hashes into hash_tree only if they have a duplicate in the db.
 * The extent search is later run on the resulting hash_tree.
 */
int dbfile_load_block_hashes(struct dbhandle *db, struct hash_tree *hash_tree,
			     unsigned int seq);
int dbfile_load_extent_hashes(struct dbhandle *db, struct results_tree *res,
			      unsigned int seq);

struct file_extent {
	uint64_t	poff;
	uint64_t	loff;
	uint64_t	len;
};
int dbfile_load_nondupe_file_extents(struct dbhandle *db, struct filerec *file,
				     struct file_extent **ret_extents,
				     unsigned int *num_extents);
int dbfile_load_one_file_extent(struct dbhandle *db, struct filerec *file,
				uint64_t loff, struct file_extent *extent);

int dbfile_load_one_filerec(struct dbhandle *db, int64_t fileid,
				struct filerec **file);

/*
 * Following are used during file scan stage to get our hashes into
 * the database.
 */
struct dbhandle *dbfile_get_handle(void);

int64_t dbfile_store_file_info(struct dbhandle *db, struct file *dbfile);
int dbfile_store_block_hashes(struct dbhandle *db, int64_t fileid,
				uint64_t nb_hash, struct block_csum *hashes);
int dbfile_store_extent_hashes(struct dbhandle *db, int64_t fileid,
				uint64_t nb_hash, struct extent_csum *hashes);
int dbfile_update_scanned_file(struct dbhandle *db, int64_t fileid,
				unsigned char *digest, unsigned int flags);
int dbfile_begin_trans(sqlite3 *db);
int dbfile_commit_trans(sqlite3 *db);
int dbfile_abort_trans(sqlite3 *db);
int dbfile_update_extent_poff(struct dbhandle *db, int64_t fileid,
				uint64_t loff, uint64_t poff);

/*
 * This is used for printing so we can get away with chars from sqlite
 * for now.
 */
typedef void (*iter_files_func)(char *filename, char *ino, char *subvol);
int dbfile_iter_files(struct dbhandle *db, iter_files_func func);

int dbfile_remove_extent_hashes(struct dbhandle *db, int64_t fileid);
int dbfile_remove_file(struct dbhandle *db, const char *filename);

void dbfile_list_files(struct dbhandle *db, int (*callback)(void*, int, char**, char**));

int dbfile_describe_file(struct dbhandle *db, uint64_t ino, uint64_t subvol,
				struct file *dbfile);
int dbfile_load_same_files(struct dbhandle *db, struct results_tree *res,
			   unsigned int seq);

int dbfile_rename_file(struct dbhandle *db, int64_t fileid, char *path);

static inline void sqlite3_stmt_cleanup(void *p)
{
	sqlite3_finalize(*(sqlite3_stmt**) p);
}

static inline void sqlite3_close_cleanup(struct dbhandle **db)
{
	dbfile_close_handle(*db);
}

static inline void sqlite3_reset_stmt(sqlite3_stmt **stmt)
{
	sqlite3_reset(*stmt);
}

void dbfile_set_gdb(struct dbhandle *db);
int dbfile_remove_hashes(struct dbhandle *db, int64_t fileid);

unsigned int get_max_dedupe_seq(struct dbhandle *db);
int dbfile_prune_unscanned_files(struct dbhandle *db);
#endif	/* __DBFILE_H__ */
