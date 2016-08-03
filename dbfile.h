#ifndef	__DBFILE_H__
#define	__DBFILE_H__

#include <sqlite3.h>
struct filerec;
struct block;

int dbfile_create(char *filename, int *dbfile_is_new);
int dbfile_open(char *filename);
void dbfile_close(void);

/* TODO: Clean up this ridiculous prototype. */
int dbfile_get_config(unsigned int *block_size, uint64_t *num_hashes,
		      uint64_t *num_files, dev_t *onefs_dev,
		      uint64_t *onefs_fsid, int *major, int *minor,
		      char *db_hash_type, unsigned int *db_dedupe_seq);
int dbfile_sync_config(unsigned int block_size, dev_t onefs_dev,
		       uint64_t onefs_fsid, unsigned int seq);

struct hash_tree;
struct hash_file_header;
struct rb_root;

int create_indexes(sqlite3 *db);

/*
 * Load hashes into hash_tree only if they have a duplicate in the db.
 * The extent search is later run on the resulting hash_tree.
 */
int dbfile_load_hashes(struct hash_tree *hash_tree);

/* Scan files based on db contents. Removes any orphaned file records. */
int dbfile_scan_files(void);

/* Write any filerecs marked as needing update to the db */
int dbfile_sync_files(sqlite3 *db);

/*
 * Following are used during file scan stage to get our hashes into
 * the database.
 */
sqlite3 *dbfile_get_handle(void);
int dbfile_write_file_info(sqlite3 *db, struct filerec *file);
int dbfile_write_hashes(sqlite3 *db, struct filerec *file,
			uint64_t nb_hash, struct block *hashes);
int dbfile_begin_trans(sqlite3 *db);
int dbfile_commit_trans(sqlite3 *db);

/*
 * This is used for printing so we can get away with chars from sqlite
 * for now.
 */
typedef void (*iter_files_func)(char *filename, char *ino, char *subvol);
int dbfile_iter_files(sqlite3 *db, iter_files_func func);

int dbfile_remove_file(sqlite3 *db, const char *filename);

#endif	/* __DBFILE_H__ */
