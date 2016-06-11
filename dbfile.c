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

#include "file_scan.h"

#include "dbfile.h"

#define DB_FILE_MAJOR	1
#define DB_FILE_MINOR	2

/* exported for hashstats.c */
sqlite3 *gdb = NULL;

#if (SQLITE_VERSION_NUMBER < 3007015)
#define	perror_sqlite(_err, _why)					\
	fprintf(stderr, "%s(): Database error %d while %s: %s\n",	\
		__FUNCTION__, _err, _why, "[sqlite3_errstr() unavailable]")
#else
#define	perror_sqlite(_err, _why)					\
	fprintf(stderr, "%s(): Database error %d while %s: %s\n",	\
		__FUNCTION__, _err, _why, sqlite3_errstr(_err))
#endif

#define	perror_sqlite_open(_ptr, _filename)				\
	fprintf(stderr, "Error opening db \"%s\": %s\n", _filename,	\
		sqlite3_errmsg(_ptr))

sqlite3 *dbfile_get_handle(void)
{
	return gdb;
}

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

#define CREATE_TABLE_CONFIG	\
"CREATE TABLE config(keyname TEXT PRIMARY KEY NOT NULL, keyval BLOB);"
	ret = sqlite3_exec(db, CREATE_TABLE_CONFIG, NULL, NULL, NULL);
	if (ret)
		goto out;

#define	CREATE_TABLE_FILES	\
"CREATE TABLE files(filename TEXT PRIMARY KEY NOT NULL, ino INTEGER, "\
"subvol INTEGER, size INTEGER, blocks INTEGER);"
	ret = sqlite3_exec(db, CREATE_TABLE_FILES, NULL, NULL, NULL);
	if (ret)
		goto out;

#define	CREATE_TABLE_HASHES					\
"CREATE TABLE hashes(digest BLOB KEY NOT NULL, ino INTEGER, subvol INTEGER, loff INTEGER, flags INTEGER);"
	ret = sqlite3_exec(db, CREATE_TABLE_HASHES, NULL, NULL, NULL);
	if (ret)
		goto out;

out:
	return ret;
}

int create_indexes(sqlite3 *db)
{
	int ret;
#define	CREATE_DIGEST_INDEX						\
"create index if not exists idx_digest on hashes(digest);"
	ret = sqlite3_exec(db, CREATE_DIGEST_INDEX, NULL, NULL, NULL);

	return ret;
}

static int dbfile_set_modes(sqlite3 *db)
{
	int ret;

	ret = sqlite3_exec(db, "PRAGMA synchronous = OFF", NULL, NULL, NULL);
	if (ret) {
		perror_sqlite(ret, "configuring database (sync pragma)");
		return ret;
	}

	ret = sqlite3_exec(db, "PRAGMA journal_mode = MEMORY", NULL, NULL, NULL);
	if (ret)
		perror_sqlite(ret, "configuring database (journal pragma)");

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

	ret = dbfile_set_modes(db);
	if (ret) {
		perror_sqlite(ret, "setting journal modes");
		sqlite3_close(db);
		return ret;
	}

	gdb = db;
	return 0;
}

int dbfile_open(char *filename)
{
	int ret;
	sqlite3 *db;

	ret = sqlite3_open_v2(filename, &db, OPEN_FLAGS, NULL);
	if (ret) {
		perror_sqlite_open(db, filename);
		sqlite3_close(db);
		return ret;
	}

	ret = dbfile_set_modes(db);
	if (ret) {
		perror_sqlite(ret, "setting journal modes");
		sqlite3_close(db);
		return ret;
	}

	gdb = db;
	return 0;
}

void dbfile_close(void)
{
	if (gdb)
		sqlite3_close(gdb);
	gdb = NULL;
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

int dbfile_sync_config(unsigned int block_size)
{
	sqlite3 *db;
	int ret;

	db = dbfile_get_handle();
	if (!db)
		return ENOENT;

	ret = __dbfile_sync_config(db, block_size);

	return ret;
}

static int __dbfile_count_rows(sqlite3_stmt *stmt, uint64_t *num)
{
	int ret;

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
#define COUNT_HASHES "select COUNT(*) from hashes;"
		ret = sqlite3_prepare_v2(db, COUNT_HASHES, -1, &stmt, NULL);
		if (ret)
			goto out;

		ret = __dbfile_count_rows(stmt, num_hashes);
		if (ret)
			goto out;

		sqlite3_finalize(stmt);
		stmt = NULL;
	}

	if (num_files) {
#define COUNT_FILES "select COUNT(*) from files;"
		ret = sqlite3_prepare_v2(db, COUNT_FILES, -1, &stmt, NULL);
		if (ret)
			goto out;

		ret = __dbfile_count_rows(stmt, num_files);
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

int dbfile_get_config(unsigned int *block_size, uint64_t *num_hashes,
		      uint64_t *num_files, int *major, int *minor)
{
	int ret;

	ret = __dbfile_get_config(gdb, block_size, num_hashes, num_files, major,
				  minor);

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

	ret = sqlite3_bind_int64(stmt, 4, file->size);
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

	ret = sqlite3_exec(db, "COMMIT TRANSACTION", NULL, NULL, &errorstr);
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

int dbfile_load_hashes(struct hash_tree *hash_tree)
{
	int ret;
	sqlite3 *db;
	sqlite3_stmt *stmt = NULL;
	uint64_t subvol, ino, loff;
	unsigned char *digest;
	int flags;
	struct filerec *file;

	db = dbfile_get_handle();
	if (!db)
		return ENOENT;

	ret = dbfile_check_version(db);
	if (ret)
		return ret;

#define GET_DUPLICATE_HASHES \
	"SELECT hashes.digest, ino, subvol, loff, flags FROM hashes " \
	"JOIN (SELECT digest FROM hashes GROUP BY digest " \
				"HAVING count(*) > 1) AS duplicate_hashes " \
	"on hashes.digest = duplicate_hashes.digest;"

	ret = sqlite3_prepare_v2(db, GET_DUPLICATE_HASHES, -1, &stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing statement");
		return ret;
	}

	while ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {
		digest = (unsigned char *)sqlite3_column_blob(stmt, 0);
		ino = sqlite3_column_int64(stmt, 1);
		subvol = sqlite3_column_int64(stmt, 2);
		loff = sqlite3_column_int64(stmt, 3);
		flags = sqlite3_column_int(stmt, 4);

		file = filerec_find(ino, subvol);
		if (!file) {
			ret = ENOENT;
			fprintf(stderr,
				"Filerec (%"PRIu64",%"PRIu64" is in db"
				" but not in hash!\n", ino, subvol);
			goto out;
		}

		ret = insert_hashed_block(hash_tree, digest, file, loff, flags);
		if (ret)
			return ENOMEM;
	}
	if (ret != SQLITE_DONE) {
		perror_sqlite(ret, "looking up hash");
		goto out;
	}
	sqlite3_reset(stmt);

	ret = 0;
out:
	if (stmt)
		sqlite3_finalize(stmt);

	return ret;
}
