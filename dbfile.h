#ifndef	__DBFILE_H__
#define	__DBFILE_H__

#include <sqlite3.h>
struct filerec;
struct block;

int dbfile_create(char *filename);
int dbfile_open(char *filename);
void dbfile_close(void);

int dbfile_get_config(unsigned int *block_size,
		      uint64_t *num_hashes, uint64_t *num_files,
		      int *major, int *minor);
int dbfile_sync_config(unsigned int block_size);

struct hash_tree;
struct hash_file_header;
struct rb_root;

/*
 * Scans hashes by digest, adding each one to our bloom filter. If we
 * find a duplicate, it is inserted into d_tree.
 *
 * This effectively does 'scan #1' for us when we're loading from a
 * dbfile instead of doing a file scan.
 */
int dbfile_populate_hashes(struct rb_root *d_tree);

/*
 * Load hashes into hash_tree only if they have a duplicate in the db.
 * The extent search is later run on the resulting hash_tree.
 */
int dbfile_load_hashes(struct hash_tree *scan_tree);

/*
 * Following are used during file scan stage to get our hashes into
 * the database.
 */
sqlite3 *dbfile_get_handle(void);
int dbfile_write_file_info(sqlite3 *db, struct filerec *file);
int dbfile_write_hashes(sqlite3 *db, struct filerec *file,
			uint64_t nb_hash, struct block *hashes);

#endif	/* __DBFILE_H__ */
