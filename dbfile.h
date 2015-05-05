#ifndef	__DBFILE_H__
#define	__DBFILE_H__

#include <sqlite3.h>
struct filerec;
struct block;

int dbfile_create(char *filename);
int dbfile_get_config(char *filename, unsigned int *block_size,
		      uint64_t *num_hashes, uint64_t *num_files,
		      int *major, int *minor);
int dbfile_sync_config(char *filename,	unsigned int block_size);

struct hash_tree;
struct hash_file_header;
/* Used by tools, will load *all* hashes into 'hash_tree' */
int dbfile_read_all_hashes(char *dbfile, struct hash_tree *tree);
struct rb_root;

/*
 * Scans hashes by digest, adding each one to our bloom filter. If we
 * find a duplicate, it is inserted into d_tree.
 *
 * This effectively does 'scan #1' for us when we're loading from a
 * dbfile instead of doing a file scan.
 */
int dbfile_populate_hashes(char *filename, struct rb_root *d_tree);

/*
 * Load hashes into hash_tree only if they are found in our bloom
 * filter. The extent search is later run on the resulting hash_tree.
 *
 * This is 'stage 2' when we're using dbfile for swap
 */
int dbfile_load_hashes_bloom(char *filename, struct hash_tree *scan_tree,
			     struct rb_root *digest_tree);

/*
 * Following are used during file scan stage to get our hashes into
 * the database. The ctxt allows us to compile our sqlite statements
 * in open once instead of on every insert.
 *
 * TODO: We can do better by compiling before launching our file scan
 * threads thus removing the need to do it during open.
 */
struct dbfile_write_ctxt {
	sqlite3		*db;
	sqlite3_stmt	*file_stmt;
	sqlite3_stmt	*hash_stmt;
};
int dbfile_open_write(char *filename, struct dbfile_write_ctxt *ctxt);
void dbfile_close_write(struct dbfile_write_ctxt *ctxt);
int dbfile_write_file_info(struct dbfile_write_ctxt *ctxt, struct filerec *file);
int dbfile_write_hashes(struct dbfile_write_ctxt *ctxt, struct filerec *file,
			uint64_t nb_hash, struct block *hashes);

#endif	/* __DBFILE_H__ */
