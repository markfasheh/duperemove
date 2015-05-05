#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sqlite3.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <stddef.h>

#include "csum.h"
#include "filerec.h"
#include "hash-tree.h"
#include "serialize.h"

#include "bloom.h"

#include "file_scan.h"

#include "dbfile.h"

#define DB_FILE_MAJOR	1
#define DB_FILE_MINOR	2

#define	perror_sqlite(_err, _why)					\
	fprintf(stderr, "%s(): Database error %d while %s: %s\n",	\
		__FUNCTION__, _err, _why, sqlite3_errstr(_err))

#define	perror_sqlite_open(_ptr, _filename)				\
	fprintf(stderr, "Error opening db \"%s\": %s\n", _filename,	\
		sqlite3_errmsg(_ptr))

#if 0
static int debug_print_cb(void *priv, int argc, char **argv, char **column)
{
	int i;

	printf("(");
	for(i = 0; i < argc; i++)
		printf("%s:%s, ", column[i], argv[i]);
	printf(")\n");
	return 0;
}
#endif

static int create_tables(sqlite3 *db)
{
	int ret;
	char *errorstr = NULL;

#define CREATE_TABLE_CONFIG	\
"CREATE TABLE config(keyname TEXT PRIMARY KEY NOT NULL, keyval BLOB);"
	ret = sqlite3_exec(db, CREATE_TABLE_CONFIG, NULL, db, &errorstr);
	if (ret)
		goto out;

#define	CREATE_TABLE_FILES	\
"CREATE TABLE files(filename TEXT PRIMARY KEY NOT NULL, ino INTEGER, "\
"subvol INTEGER, size INTEGER, blocks INTEGER);"
	ret = sqlite3_exec(db, CREATE_TABLE_FILES, NULL, db, &errorstr);
	if (ret)
		goto out;

#define	CREATE_TABLE_HASHES					\
"CREATE TABLE hashes(digest BLOB KEY NOT NULL, ino INTEGER, subvol INTEGER, loff INTEGER, flags INTEGER);"
	ret = sqlite3_exec(db, CREATE_TABLE_HASHES, NULL, db, &errorstr);
	if (ret)
		goto out;

#define CREATE_HASHES_INDEX						\
"create index idx_inosub on hashes(ino, subvol);"

	ret = sqlite3_exec(db, CREATE_HASHES_INDEX, NULL, db, &errorstr);
out:

	sqlite3_free(errorstr);

	return ret;
}

int dbfile_create(char *filename)
{
	int ret;
	sqlite3 *db = NULL;

	ret = unlink(filename);
	if (ret && errno != ENOENT) {
		ret = errno;
		fprintf(stderr,
			"Error %d while unlinking old db file \"%s\": %s",
			ret, filename, strerror(ret));
		return ret;
	}

#define OPEN_FLAGS	(SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_NOMUTEX)
	ret = sqlite3_open_v2(filename, &db, OPEN_FLAGS, NULL);
	if (ret) {
		perror_sqlite_open(db, filename);
		return ret;
	}

	ret = create_tables(db);
	if (ret) {
		perror_sqlite(ret, "creating tables");
		sqlite3_close(db);
		return ret;
	}

	sqlite3_close(db);
	return ret;
}

sqlite3 *dbfile_open(char *filename)
{
	int ret;
	sqlite3 *db;

	ret = sqlite3_open_v2(filename, &db, OPEN_FLAGS, NULL);
	if (ret) {
		perror_sqlite_open(db, filename);
		sqlite3_close(db);
		return NULL;
	}

	return db;
}

void dbfile_close(sqlite3 *db)
{
	if (db)
		sqlite3_close(db);
}

int __dbfile_sync_config(sqlite3 *db, unsigned int block_size)
{
	int ret;
	sqlite3_stmt *stmt = NULL;

	ret = sqlite3_prepare_v2(db,
				 "INSERT INTO config VALUES (?1, ?2)", -1,
				 &stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing statement");
		return ret;
	}

	ret = sqlite3_bind_text(stmt, 1, "version_major", -1, SQLITE_STATIC);
	if (ret)
		goto out;
	ret = sqlite3_bind_int(stmt, 2, DB_FILE_MAJOR);
	if (ret)
		goto out;
	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE)
		goto out;
	sqlite3_reset(stmt);

	ret = sqlite3_bind_text(stmt, 1, "version_minor", -1, SQLITE_STATIC);
	if (ret)
		goto out;
	ret = sqlite3_bind_int(stmt, 2, DB_FILE_MINOR);
	if (ret)
		goto out;
	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE)
		goto out;
	sqlite3_reset(stmt);

	ret = sqlite3_bind_text(stmt, 1, "hash_type", -1, SQLITE_STATIC);
	if (ret)
		goto out;
	ret = sqlite3_bind_text(stmt, 2, hash_type, 8, SQLITE_TRANSIENT);
	if (ret)
		goto out;
	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE)
		goto out;
	sqlite3_reset(stmt);

	ret = sqlite3_bind_text(stmt, 1, "block_size", -1, SQLITE_STATIC);
	if (ret)
		goto out;
	ret = sqlite3_bind_int(stmt, 2, block_size);
	if (ret)
		goto out;
	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE)
		goto out;
	sqlite3_reset(stmt);

	ret = 0;
out:
	sqlite3_finalize(stmt);

	if (ret) {
		perror_sqlite(ret, "binding");
	}

	return ret;
}

int dbfile_sync_config(char *filename, unsigned int block_size)
{
	sqlite3 *db;
	int ret;

	db = dbfile_open(filename);
	if (!db)
		return ENOENT;

	ret = __dbfile_sync_config(db, block_size);

	dbfile_close(db);

	return ret;
}

static int __dbfile_count_rows(sqlite3_stmt *stmt, const char *rowid,
			       uint64_t *num)
{
	int ret;

	ret = sqlite3_bind_text(stmt, 1, rowid, -1, SQLITE_STATIC);
	if (ret) {
		perror_sqlite(ret, "retrieving count from table (bind)");
		return ret;
	}

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_ROW) {
		perror_sqlite(ret, "retrieving count from table (step)");
		return ret;
	}

	*num = sqlite3_column_int64(stmt, 0);

	sqlite3_reset(stmt);

	return 0;
}

static int dbfile_count_rows(sqlite3 *db, uint64_t *num_hashes,
			     uint64_t *num_files)
{
	int ret = 0;
	sqlite3_stmt *stmt = NULL;

	if (num_hashes) {
#define COUNT_HASHES "select COUNT(?1) from hashes;"
		ret = sqlite3_prepare_v2(db, COUNT_HASHES, -1, &stmt, NULL);
		if (ret)
			goto out;

		ret = __dbfile_count_rows(stmt, "digest", num_hashes);
		if (ret)
			goto out;

		sqlite3_finalize(stmt);
		stmt = NULL;
	}

	if (num_files) {
#define COUNT_FILES "select COUNT(?1) from files;"
		ret = sqlite3_prepare_v2(db, COUNT_FILES, -1, &stmt, NULL);
		if (ret)
			goto out;

		ret = __dbfile_count_rows(stmt, "filename", num_files);
		if (ret)
			goto out;

		sqlite3_finalize(stmt);
		stmt = NULL;
	}
out:
	if (stmt)
		sqlite3_finalize(stmt);

	return ret;
}

static int get_config_int(sqlite3_stmt *stmt, const char *name, int *val)
{
	int ret;

	if (!val)
		return 0;

	ret = sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
	if (ret) {
		perror_sqlite(ret, "retrieving row from config table (bind)");
		return ret;
	}

	while ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {
		*val = sqlite3_column_int(stmt, 0);
	}
	if (ret != SQLITE_DONE) {
		perror_sqlite(ret, "retrieving row from config table (step)");
		return ret;
	}

	sqlite3_reset(stmt);

	return 0;
}

static int __dbfile_get_config(sqlite3 *db, unsigned int *block_size,
			       uint64_t *num_hashes, uint64_t *num_files,
			       int *major, int *minor)
{
	int ret;
	sqlite3_stmt *stmt = NULL;

#define SELECT_CONFIG "select keyval from config where keyname=?1;"
	ret = sqlite3_prepare_v2(db, SELECT_CONFIG, -1, &stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing statement");
		goto out;
	}

	ret = get_config_int(stmt, "block_size", (int *)block_size);
	if (ret)
		goto out;

	ret = get_config_int(stmt, "version_major", major);
	if (ret)
		goto out;

	ret = get_config_int(stmt, "version_minor", minor);
	if (ret)
		goto out;

	sqlite3_finalize(stmt);
	stmt = NULL;

	ret = dbfile_count_rows(db, num_hashes, num_files);
	if (ret)
		goto out;

out:
	if (stmt)
		sqlite3_finalize(stmt);
	return ret;
}

int dbfile_get_config(char *filename, unsigned int *block_size,
		      uint64_t *num_hashes, uint64_t *num_files, int *major,
		      int *minor)
{
	int ret;
	sqlite3 *db;

	db = dbfile_open(filename);
	if (!db)
		return ENOENT;

	ret = __dbfile_get_config(db, block_size, num_hashes, num_files, major,
				  minor);

	dbfile_close(db);
	return ret;
}

static int dbfile_check_version(sqlite3 *db)
{
	int ret;
	int major, minor;

	ret = __dbfile_get_config(db, NULL, NULL, NULL, &major, &minor);
	if (ret)
		return ret;

	if (major > DB_FILE_MAJOR) {
		fprintf(stderr,
			"Hash db version mismatch (mine: %d.%d, file: %d.%d)\n",
			DB_FILE_MAJOR, DB_FILE_MINOR, major, minor);
		return EIO;
	}

	/* XXX: Check hash type here! */

	return 0;
}

int dbfile_write_file_info(sqlite3 *db, struct filerec *file)
{
	int ret;
	sqlite3_stmt *stmt = NULL;

#define	WRITE_FILE							\
"INSERT INTO files (ino, subvol, filename, size, blocks) VALUES (?1, ?2, ?3, ?4, ?5);"
	ret = sqlite3_prepare_v2(db, WRITE_FILE, -1, &stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing filerec insert statement");
		goto out_error;
	}

	ret = sqlite3_bind_int64(stmt, 1, file->inum);
	if (ret)
		goto bind_error;

	ret = sqlite3_bind_int64(stmt, 2, file->subvolid);
	if (ret)
		goto bind_error;

	ret = sqlite3_bind_text(stmt, 3, file->filename, -1, SQLITE_STATIC);
	if (ret)
		goto bind_error;

	ret = sqlite3_bind_int64(stmt, 4, 0ULL);
	if (ret)
		goto bind_error;

	ret = sqlite3_bind_int64(stmt, 5, file->num_blocks);
	if (ret)
		goto bind_error;

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE) {
		perror_sqlite(ret, "executing sql");
		goto out_error;
	}

	ret = 0;
bind_error:
	if (ret)
		perror_sqlite(ret, "binding values");
out_error:

	sqlite3_finalize(stmt);
	return ret;
}

int dbfile_write_hashes(sqlite3 *db, struct filerec *file, uint64_t nb_hash,
			struct block *hashes)
{
	int ret;
	uint64_t i;
	char *errorstr = NULL;
	sqlite3_stmt *stmt = NULL;
	uint64_t loff;
	uint32_t flags;
	unsigned char *digest;

	ret = sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, &errorstr);
	if (ret) {
		perror_sqlite(ret, "starting transaction");
		sqlite3_free(errorstr);
		return ret;
	}

#define	UPDATE_HASH						\
"INSERT INTO hashes (ino, subvol, loff, flags, digest) VALUES (?1, ?2, ?3, ?4, ?5);"
	ret = sqlite3_prepare_v2(db, UPDATE_HASH, -1, &stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing hash insert statement");
		goto out_error;
	}

	for (i = 0; i < nb_hash; i++) {
		loff = hashes[i].loff;
		flags = hashes[i].flags;
		digest = hashes[i].digest;

		ret = sqlite3_bind_int64(stmt, 1, file->inum);
		if (ret)
			goto bind_error;

		ret = sqlite3_bind_int64(stmt, 2, file->subvolid);
		if (ret)
			goto bind_error;

		ret = sqlite3_bind_int64(stmt, 3, loff);
		if (ret)
			goto bind_error;

		ret = sqlite3_bind_int(stmt, 4, flags);
		if (ret)
			goto bind_error;

		ret = sqlite3_bind_blob(stmt, 5, digest, digest_len,
					SQLITE_STATIC);
		if (ret)
			goto bind_error;

		ret = sqlite3_step(stmt);
		if (ret != SQLITE_DONE) {
			perror_sqlite(ret, "executing statement");
			goto out_error;
		}

		sqlite3_reset(stmt);
	}

	ret = sqlite3_exec(db, "COMMIT TRANSACTION", NULL, db, &errorstr);
	if (ret) {
		perror_sqlite(ret, "committing transaction");
		sqlite3_free(errorstr);
	}

	ret = 0;
bind_error:
	if (ret)
		perror_sqlite(ret, "binding values");
out_error:

	sqlite3_finalize(stmt);
	return ret;
}

typedef int (walk_file_hashes_cb)(struct filerec *file, unsigned char *digest,
				   uint64_t loff, int flags, void *priv);

static int dbfile_walk_file_hashes(sqlite3 *db, struct filerec *file,
				   walk_file_hashes_cb *cb, void *priv)
{
	int ret;
	sqlite3_stmt *stmt = NULL;
	unsigned char *digest;
	uint64_t loff;
	unsigned int flags;

#define	LOAD_HASHES_SQL	\
"SELECT digest, loff, flags FROM hashes WHERE ino = ?1 AND subvol = ?2 ORDER BY loff;"

	ret = sqlite3_prepare_v2(db, LOAD_HASHES_SQL, -1, &stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing statement");
		return ret;
	}

	ret = sqlite3_bind_int64(stmt, 1, file->inum);
	if (ret) {
		perror_sqlite(ret, "binding inum to statement");
		goto out_finalize;
	}

	ret = sqlite3_bind_int64(stmt, 2, file->subvolid);
	if (ret) {
		perror_sqlite(ret, "binding subvolid to statement");
 		goto out_finalize;
	}

	while ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {
		digest = (unsigned char *)sqlite3_column_blob(stmt, 0);
		loff = sqlite3_column_int64(stmt, 1);
		flags = sqlite3_column_int(stmt, 2);

		ret = cb(file, digest, loff, flags, priv);
		if (ret)
			goto out_finalize;
	}
	if (ret != SQLITE_DONE) {
		perror_sqlite(ret, "retrieving hashes from table");
		goto out_finalize;
	}

	ret = 0;
out_finalize:
	sqlite3_finalize(stmt);

	return ret;
}

static int load_into_hash_tree_cb(struct filerec *file, unsigned char *digest,
				  uint64_t loff, int flags, void *priv)
{
	struct hash_tree *tree = priv;

	return insert_hashed_block(tree, digest, file, loff, flags);
}

int dbfile_read_all_hashes(char *dbfile, struct hash_tree *tree)
{
	int ret;
	sqlite3 *db;
	sqlite3_stmt *stmt = NULL;
	char *filename;
	uint64_t ino, subvolid;
	struct filerec *file;

	db = dbfile_open(dbfile);
	if (!db)
		return ENOENT;

	ret = dbfile_check_version(db);
	if (ret)
		goto out_close;

	ret = sqlite3_prepare_v2(db,
				 "SELECT ino, subvol, filename from files;", -1,
				 &stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing statement");
		goto out_close;
	}

	while ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {
		ino = sqlite3_column_int64(stmt, 0);
		subvolid = sqlite3_column_int64(stmt, 1);
		filename = (char *)sqlite3_column_text(stmt, 2);

		file = filerec_new(filename, ino, subvolid);
		if (!file) {
			ret = ENOMEM;
			goto out_finalize;
		}

		ret = dbfile_walk_file_hashes(db, file, load_into_hash_tree_cb,
					      tree);
		if (ret)
			goto out_finalize;
	}
	if (ret != SQLITE_DONE) {
		perror_sqlite(ret, "retrieving hashes from table");
		ret = EIO;
		goto out_finalize;
	}

	ret = 0;
out_finalize:
	sqlite3_finalize(stmt);

out_close:
	dbfile_close(db);

	return ret;
}

struct bloom_cb_priv {
	struct rb_root	*d_tree;
	struct bloom	bloom;
};

static int load_into_bloom_cb(struct filerec *file, unsigned char *digest,
			      uint64_t loff, int flags, void *priv)
{
	int ret;
	struct bloom_cb_priv *p = priv;

	ret = bloom_add(&p->bloom, digest, digest_len);
	if (ret == 1) {
		ret = digest_insert(p->d_tree, digest);
		if (ret)
			return ret;
	}

	return ret;
}

int dbfile_populate_hashes(char *dbfile, struct rb_root *d_tree)
{
	int ret;
	sqlite3 *db;
	sqlite3_stmt *stmt = NULL;
	char *filename;
	uint64_t ino, subvolid;
	uint64_t num_hashes;
	struct filerec *file;
	struct bloom_cb_priv priv;

	db = dbfile_open(dbfile);
	if (!db)
		return ENOENT;

	ret = dbfile_count_rows(db, &num_hashes, NULL);
	if (ret)
		goto out_close;

	priv.d_tree = d_tree;
	ret = bloom_init(&priv.bloom, num_hashes, 0.01);
	if (ret)
		goto out_bloom;

	ret = sqlite3_prepare_v2(db,
				 "SELECT ino, subvol, filename from files;", -1,
				 &stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing statement");
		goto out_bloom;
	}

	while ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {
		ino = sqlite3_column_int64(stmt, 0);
		subvolid = sqlite3_column_int64(stmt, 1);
		filename = (char *)sqlite3_column_text(stmt, 2);

		file = filerec_new(filename, ino, subvolid);
		if (!file) {
			ret = ENOMEM;
			goto out_finalize;
		}

		ret = dbfile_walk_file_hashes(db, file, load_into_bloom_cb,
					      &priv);
		if (ret)
			goto out_finalize;
	}
	if (ret != SQLITE_DONE) {
		perror_sqlite(ret, "retrieving file info from table");
		goto out_finalize;
	}

	ret = 0;
out_finalize:
	sqlite3_finalize(stmt);
out_bloom:
	bloom_free(&priv.bloom);
out_close:
	dbfile_close(db);

	return ret;
}

int dbfile_load_hashes_bloom(char *dbfile, struct hash_tree *hash_tree,
			     struct rb_root *d_tree)
{
	int ret;
	struct rb_node *d_hash_node = rb_first(d_tree);
	struct d_tree *d_hash;
	sqlite3 *db;
	sqlite3_stmt *stmt = NULL;
	uint64_t subvol, ino, loff;
	int flags;
	struct filerec *file;

	db = dbfile_open(dbfile);
	if (!db)
		return ENOENT;

	ret = sqlite3_prepare_v2(db,
	 "SELECT ino, subvol, loff, flags FROM hashes WHERE digest = ?1;",
				 -1, &stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing statement");
		return ret;
	}

	for (d_hash_node = rb_first(d_tree); d_hash_node;
	     d_hash_node = rb_next(d_hash_node)) {
		d_hash = rb_entry(d_hash_node, struct d_tree, t_node);

		/*
		 * XXX: Using SQLITE_STATIC here because it's probably
		 * faster. If we ever free items from d_tree, we need
		 * to change that.
		 */
		ret = sqlite3_bind_blob(stmt, 1, d_hash->digest,
					digest_len, SQLITE_STATIC);
		if (ret) {
			perror_sqlite(ret, "looking up hash (bind)");
			goto out;
		}

		while ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {
			ino = sqlite3_column_int64(stmt, 0);
			subvol = sqlite3_column_int64(stmt, 1);
			loff = sqlite3_column_int64(stmt, 2);
			flags = sqlite3_column_int(stmt, 3);

			file = filerec_find(ino, subvol);
			if (!file) {
				ret = ENOENT;
				fprintf(stderr,
					"Filerec (%"PRIu64",%"PRIu64" is in db"
					" but not in hash!\n", ino, subvol);
				goto out;
			}

			ret = insert_hashed_block(hash_tree, d_hash->digest,
						  file, loff, flags);
			if (ret)
				return ENOMEM;
		}
		if (ret != SQLITE_DONE) {
			perror_sqlite(ret, "looking up hash");
			goto out;
		}
		sqlite3_reset(stmt);
	}

	ret = 0;
out:
	if (stmt)
		sqlite3_finalize(stmt);

	dbfile_close(db);

	return ret;
}
