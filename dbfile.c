#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sqlite3.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <stddef.h>
#include <sys/types.h>

#include "csum.h"
#include "filerec.h"
#include "hash-tree.h"

#include "file_scan.h"
#include "debug.h"

#include "dbfile.h"

#define DB_FILE_MAJOR	2
#define DB_FILE_MINOR	0

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

static int __dbfile_get_config(sqlite3 *db, unsigned int *block_size,
			       uint64_t *num_hashes, uint64_t *num_files,
			       dev_t *onefs_dev, uint64_t *onefs_fsid,
			       int *major, int *minor, char *db_hash_type,
			       unsigned int *db_dedupe_seq);

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
"subvol INTEGER, size INTEGER, blocks INTEGER, mtime INTEGER, dedupe_seq INTEGER);"
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
	if (ret)
		goto out;

#define	CREATE_HASHES_INO_INDEX						\
"create index if not exists idx_hashes_inosub on hashes(ino, subvol);"
	ret = sqlite3_exec(db, CREATE_HASHES_INO_INDEX, NULL, NULL, NULL);
	if (ret)
		goto out;

#define	CREATE_INO_INDEX						\
"create index if not exists idx_inosub on files(ino, subvol);"
	ret = sqlite3_exec(db, CREATE_INO_INDEX, NULL, NULL, NULL);

out:
	if (ret)
		perror_sqlite(ret, "creating database index");
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

	return ret;
}

int dbfile_create(char *filename, int *dbfile_is_new)
{
	int ret, inmem = 0, newfile = 0;
	sqlite3 *db = NULL;
	int vmajor, vminor;

	if (!filename) {
		inmem = 1;
		/*
		 * Set this so main() doesn't try to get config, etc
		 * from a memory file.
		 */
		newfile = 1;
		filename = ":memory:";
	} else {
		ret = access(filename, R_OK|W_OK);
		if (ret == -1 && errno == ENOENT)
			newfile = 1;
	}

reopen:
#define OPEN_FLAGS	(SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_NOMUTEX)
	ret = sqlite3_open_v2(filename, &db, OPEN_FLAGS, NULL);
	if (ret) {
		perror_sqlite_open(db, filename);
		return ret;
	}

	if (newfile || inmem) {
		ret = create_tables(db);
		if (ret) {
			perror_sqlite(ret, "creating tables");
			sqlite3_close(db);
			return ret;
		}
	} else {
		ret = __dbfile_get_config(db, NULL, NULL, NULL, NULL, NULL,
					  &vmajor, &vminor, NULL, NULL);
		if (ret && ret != SQLITE_CORRUPT) {
			perror_sqlite(ret, "reading initial db config");
			sqlite3_close(db);
			return ret;
		}

		if (ret || vmajor <= 1) {
			/*
			 * Behavior for v1 dbfiles was to delete
			 * them on every run. They also didn't store
			 * mtime so any attempt to 'upgrade' would
			 * include rescanning all files anyway.
			 */
			sqlite3_close(db);
			ret = unlink(filename);
			if (ret && errno != ENOENT) {
				ret = errno;
				fprintf(stderr, "Error %d while unlinking old "
					"or damaged db file \"%s\": %s", ret,
					filename, strerror(ret));
				return ret;
			}
			newfile = 1;
			goto reopen;
		}

		if (vmajor != DB_FILE_MAJOR) {
			fprintf(stderr, "Error: Hashfile \"%s\" has unknown "
				"version, %d.%d (I understand %d.%d)\n",
				filename, vmajor, vminor, DB_FILE_MAJOR,
				DB_FILE_MINOR);
			sqlite3_close(db);
			return -EIO;
		}
	}

	ret = dbfile_set_modes(db);
	if (ret) {
		perror_sqlite(ret, "setting journal modes");
		sqlite3_close(db);
		return ret;
	}

	*dbfile_is_new = newfile;
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

int dbfile_begin_trans(sqlite3 *db)
{
	int ret;

	ret = sqlite3_exec(db, "begin transaction", NULL, NULL, NULL);
	if (ret)
		perror_sqlite(ret, "starting transaction");
	return ret;
}

int dbfile_commit_trans(sqlite3 *db)
{
	int ret;

	ret = sqlite3_exec(db, "commit transaction", NULL, NULL, NULL);
	if (ret)
		perror_sqlite(ret, "committing transaction");
	return ret;
}

static int sync_config_text(sqlite3_stmt *stmt, const char *key, char *val,
			    int len)
{
	int ret;

	ret = sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
	if (ret)
		goto out;
	ret = sqlite3_bind_text(stmt, 2, val, len, SQLITE_TRANSIENT);
	if (ret)
		goto out;
	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE)
		goto out;
	sqlite3_reset(stmt);

	ret = 0;
out:
	return ret;
}

static int sync_config_int(sqlite3_stmt *stmt, const char *key, int val)
{
	int ret;

	ret = sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
	if (ret)
		goto out;
	ret = sqlite3_bind_int(stmt, 2, val);
	if (ret)
		goto out;
	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE)
		goto out;
	sqlite3_reset(stmt);

	ret = 0;
out:
	return ret;
}

static int sync_config_int64(sqlite3_stmt *stmt, const char *key, uint64_t val)
{
	int ret;

	ret = sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
	if (ret)
		goto out;
	ret = sqlite3_bind_int64(stmt, 2, val);
	if (ret)
		goto out;
	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE)
		goto out;
	sqlite3_reset(stmt);

	ret = 0;
out:
	return ret;
}

int __dbfile_sync_config(sqlite3 *db, unsigned int block_size, dev_t onefs_dev,
			 uint64_t onefs_fsid, unsigned int seq)
{
	int ret;
	sqlite3_stmt *stmt = NULL;
	unsigned int onefs_major, onefs_minor;

	ret = sqlite3_prepare_v2(db,
				 "insert or replace into config VALUES (?1, ?2)", -1,
				 &stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing statement");
		return ret;
	}

	ret = sync_config_text(stmt, "hash_type", hash_type, 8);
	if (ret)
		goto out;

	ret = sync_config_int(stmt, "block_size", block_size);
	if (ret)
		goto out;

	onefs_major = major(onefs_dev);
	ret = sync_config_int(stmt, "onefs_dev_major", onefs_major);
	if (ret)
		goto out;

	onefs_minor = minor(onefs_dev);
	ret = sync_config_int(stmt, "onefs_dev_minor", onefs_minor);
	if (ret)
		goto out;

	ret = sync_config_int64(stmt, "onefs_fsid", onefs_fsid);
	if (ret)
		goto out;

	ret = sync_config_int(stmt, "dedupe_sequence", seq);
	if (ret)
		goto out;

	ret = sync_config_int(stmt, "version_minor", DB_FILE_MINOR);
	if (ret)
		goto out;

	/*
	 * Always write version_major last so we have an easy check
	 * whether the config table was fully written.
	 */
	ret = sync_config_int(stmt, "version_major", DB_FILE_MAJOR);
	if (ret)
		goto out;

	ret = 0;
out:
	sqlite3_finalize(stmt);

	if (ret) {
		perror_sqlite(ret, "binding");
	}

	return ret;
}

int dbfile_sync_config(unsigned int block_size, dev_t onefs_dev,
		       uint64_t onefs_fsid, unsigned int seq)
{
	sqlite3 *db;
	int ret;

	db = dbfile_get_handle();
	if (!db)
		return ENOENT;

	ret = __dbfile_sync_config(db, block_size, onefs_dev, onefs_fsid, seq);

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
	int ret, found = 0;

	if (!val)
		return 0;

	ret = sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
	if (ret) {
		perror_sqlite(ret, "retrieving row from config table (bind)");
		return ret;
	}

	while ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {
		*val = sqlite3_column_int(stmt, 0);
		found++;
	}
	if (ret != SQLITE_DONE) {
		perror_sqlite(ret, "retrieving row from config table (step)");
		return ret;
	}

	if (!found)
		return SQLITE_CORRUPT;

	sqlite3_reset(stmt);

	return 0;
}

static int get_config_int64(sqlite3_stmt *stmt, const char *name, uint64_t *val)
{
	int ret, found = 0;;

	if (!val)
		return 0;

	ret = sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
	if (ret) {
		perror_sqlite(ret, "retrieving row from config table (bind)");
		return ret;
	}

	while ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {
		*val = sqlite3_column_int64(stmt, 0);
		found++;
	}
	if (ret != SQLITE_DONE) {
		perror_sqlite(ret, "retrieving row from config table (step)");
		return ret;
	}

	if (!found)
		return SQLITE_CORRUPT;

	sqlite3_reset(stmt);

	return 0;
}

static int get_config_text(sqlite3_stmt *stmt, const char *name,
			   const unsigned char *val, unsigned int len)
{
	int ret, found = 0;
	const unsigned char *local;

	if (!val)
		return 0;

	ret = sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
	if (ret) {
		perror_sqlite(ret, "retrieving row from config table (bind)");
		return ret;
	}

	while ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {
		local = sqlite3_column_text(stmt, 0);
		strncpy((char *)val, (char *)local, len);
		found++;
	}

	if (ret != SQLITE_DONE) {
		perror_sqlite(ret, "retrieving row from config table (step)");
		return ret;
	}

	if (!found)
		return SQLITE_CORRUPT;

	sqlite3_reset(stmt);

	return 0;
}

static int __dbfile_get_config(sqlite3 *db, unsigned int *block_size,
			       uint64_t *num_hashes, uint64_t *num_files,
			       dev_t *onefs_dev, uint64_t *onefs_fsid,
			       int *ver_major, int *ver_minor,
			       char *db_hash_type, unsigned int *db_dedupe_seq)
{
	int ret;
	sqlite3_stmt *stmt = NULL;
	unsigned int onefs_major, onefs_minor;

#define SELECT_CONFIG "select keyval from config where keyname=?1;"
	ret = sqlite3_prepare_v2(db, SELECT_CONFIG, -1, &stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing statement");
		goto out;
	}

	ret = get_config_int(stmt, "block_size", (int *)block_size);
	if (ret)
		goto out;

	ret = get_config_text(stmt, "hash_type",
			      (const unsigned char *)db_hash_type, 8);
	if (ret)
		goto out;

	ret = get_config_int(stmt, "version_major", ver_major);
	if (ret)
		goto out;

	ret = get_config_int(stmt, "version_minor", ver_minor);
	if (ret)
		goto out;

	if (onefs_dev) {
		ret = get_config_int(stmt, "onefs_dev_major", (int *)&onefs_major);
		if (ret)
			goto out;

		ret = get_config_int(stmt, "onefs_dev_minor", (int *)&onefs_minor);
		if (ret)
			goto out;

		*onefs_dev = makedev(onefs_major, onefs_minor);
	}

	ret = get_config_int64(stmt, "onefs_fsid", onefs_fsid);
	if (ret)
		goto out;

	ret = get_config_int(stmt, "dedupe_sequence", (int *)db_dedupe_seq);
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
		      uint64_t *num_files, dev_t *onefs_dev,
		      uint64_t *onefs_fsid, int *ver_major, int *ver_minor,
		      char *db_hash_type, unsigned int *db_dedupe_seq)
{
	int ret;

	ret = __dbfile_get_config(gdb, block_size, num_hashes, num_files,
				  onefs_dev, onefs_fsid, ver_major, ver_minor,
				  db_hash_type, db_dedupe_seq);

	return ret;
}

static int dbfile_check_version(sqlite3 *db)
{
	int ret;
	int ver_major, ver_minor;

	ret = __dbfile_get_config(db, NULL, NULL, NULL, NULL, NULL, &ver_major,
				  &ver_minor, NULL, NULL);
	if (ret)
		return ret;

	if (ver_major > DB_FILE_MAJOR) {
		fprintf(stderr,
			"Hash db version mismatch (mine: %d.%d, file: %d.%d)\n",
			DB_FILE_MAJOR, DB_FILE_MINOR, ver_major, ver_minor);
		return EIO;
	}

	/* XXX: Check hash type here! */

	return 0;
}

static int __dbfile_write_file_info(sqlite3 *db, sqlite3_stmt *stmt,
				    struct filerec *file)
{
	int ret;

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

	ret = sqlite3_bind_int64(stmt, 6, file->mtime);
	if (ret)
		goto bind_error;

	ret = sqlite3_bind_int(stmt, 7, file->dedupe_seq);
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
	return ret;
}

int dbfile_write_file_info(sqlite3 *db, struct filerec *file)
{
	int ret;
	sqlite3_stmt *stmt = NULL;

#define	WRITE_FILE							\
"insert or replace into files (ino, subvol, filename, size, blocks, mtime, dedupe_seq) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);"
	ret = sqlite3_prepare_v2(db, WRITE_FILE, -1, &stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing filerec insert statement");
		return ret;
	}

	ret = __dbfile_write_file_info(db, stmt, file);

	sqlite3_finalize(stmt);
	return ret;
}

/*
 * Write any filerec metadata which was not updated during the
 * checksumming phase.
 */
int dbfile_sync_files(sqlite3 *db)
{
	int ret;
	struct filerec *file;
	sqlite3_stmt *stmt = NULL;

	ret = sqlite3_prepare_v2(db, WRITE_FILE, -1, &stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing filerec insert statement");
		return ret;
	}

	list_for_each_entry(file, &filerec_list, rec_list) {
		if (file->flags & FILEREC_UPDATE_DB) {
			dprintf("File \"%s\" still needs update in db\n",
				file->filename);

			ret = __dbfile_write_file_info(db, stmt, file);
			if (ret)
				break;

			file->flags &= ~FILEREC_UPDATE_DB;
			sqlite3_reset(stmt);
		}
	}

	sqlite3_finalize(stmt);

	return ret;
}

static int __dbfile_remove_file_hashes(sqlite3_stmt *stmt, uint64_t ino,
				       uint64_t subvol)
{
	int ret;

	ret = sqlite3_bind_int64(stmt, 1, ino);
	if (ret) {
		perror_sqlite(ret, "binding inode");
		goto out;
	}

	ret = sqlite3_bind_int64(stmt, 2, subvol);
	if (ret) {
		perror_sqlite(ret, "binding subvol");
		goto out;
	}

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE) {
		perror_sqlite(ret, "executing statement");
		goto out;
	}

	ret = 0;
out:
	return ret;
}

static int dbfile_remove_file_hashes(sqlite3 *db, struct filerec *file)
{
	int ret;
	sqlite3_stmt *stmt = NULL;

#define	REMOVE_FILE_HASHES						\
	"delete from hashes where ino = ?1 and subvol = ?2;"
	ret = sqlite3_prepare_v2(db, REMOVE_FILE_HASHES, -1, &stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing hash insert statement");
		return ret;
	}

	ret = __dbfile_remove_file_hashes(stmt, file->inum, file->subvolid);

	sqlite3_finalize(stmt);
	return ret;
}

int dbfile_write_hashes(sqlite3 *db, struct filerec *file, uint64_t nb_hash,
			struct block *hashes)
{
	int ret;
	uint64_t i;
	sqlite3_stmt *stmt = NULL;
	uint64_t loff;
	uint32_t flags;
	unsigned char *digest;

	if (file->flags & FILEREC_IN_DB) {
		ret = dbfile_remove_file_hashes(db, file);
		if (ret)
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

	ret = 0;
bind_error:
	if (ret)
		perror_sqlite(ret, "binding values");
out_error:

	sqlite3_finalize(stmt);
	return ret;
}

struct orphan_file
{
	struct list_head	list;
	char			*filename;
	uint64_t		ino;
	uint64_t		subvol;
	char			buf[0];
};

static inline struct orphan_file *alloc_orphan_file(const char *filename,
						    uint64_t ino,
						    uint64_t subvol)
{
	int len = strlen(filename);
	struct orphan_file *o = calloc(1, sizeof(*o) + len + 1);

	if (o) {
		o->filename = o->buf;
		strncpy(o->filename, filename, len);
		INIT_LIST_HEAD(&o->list);
		o->subvol = subvol;
		o->ino = ino;
	}
	return o;
}

static void free_orphan_list(struct list_head *orphans)
{
	struct orphan_file *o, *tmp;

	list_for_each_entry_safe(o, tmp, orphans, list) {
		list_del(&o->list);
		free(o);
	}
}

/*
 * Walk the files in our db and let the code in add_file_db() sort out
 * what to do with each one.
 */
static int dbfile_load_files(struct sqlite3 *db, struct list_head *orphans)
{
	int ret, del_rec;
	sqlite3_stmt *stmt = NULL;
	const char *filename;
	uint64_t size, mtime, ino, subvol;
	unsigned int dedupe_seq;

#define	LOAD_ALL_FILERECS	"select filename, ino, subvol, size, mtime, dedupe_seq from files;"

	ret = sqlite3_prepare_v2(db, LOAD_ALL_FILERECS, -1, &stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing statement");
		return ret;
	}

	while ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {
		filename = (const char *)sqlite3_column_text(stmt, 0);
		ino = sqlite3_column_int64(stmt, 1);
		subvol = sqlite3_column_int64(stmt, 2);
		size = sqlite3_column_int64(stmt, 3);
		mtime = sqlite3_column_int64(stmt, 4);
		dedupe_seq = sqlite3_column_int(stmt, 5);

		ret = add_file_db(filename, ino, subvol, size, mtime,
				  dedupe_seq, &del_rec);
		if (ret)
			goto out;

		if (del_rec) {
			struct orphan_file *o = alloc_orphan_file(filename, ino,
								  subvol);
			if (!o) {
				ret = ENOMEM;
				fprintf(stderr, "Out of memory while loading "
					"files from database.\n");
				goto out;
			}
			list_add_tail(&o->list, orphans);
		}
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

static int dbfile_del_orphans(struct sqlite3 *db, struct list_head *orphans)
{
	int ret;
	sqlite3_stmt *files_stmt = NULL;
	sqlite3_stmt *hashes_stmt = NULL;
	struct orphan_file *o, *tmp;

#define	DELETE_FILE	"delete from files where filename = ?1;"
	ret = sqlite3_prepare_v2(db, DELETE_FILE, -1, &files_stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing files statement");
		goto out;
	}

	ret = sqlite3_prepare_v2(db, REMOVE_FILE_HASHES, -1, &hashes_stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing hashes statement");
		goto out;
	}

	list_for_each_entry_safe(o, tmp, orphans, list) {
		dprintf("Remove file \"%s\" from the db\n",
			o->filename);

		ret = __dbfile_remove_file_hashes(hashes_stmt, o->ino, o->subvol);
		if (ret)
			goto out;

		ret = sqlite3_bind_text(files_stmt, 1, o->filename, -1,
					SQLITE_TRANSIENT);
		if (ret) {
			perror_sqlite(ret, "binding filename for sql");
			goto out;
		}

		ret = sqlite3_step(files_stmt);
		if (ret != SQLITE_DONE) {
			perror_sqlite(ret, "executing sql");
			goto out;
		}

		sqlite3_reset(hashes_stmt);
		sqlite3_reset(files_stmt);

		list_del(&o->list);
		free(o);
	}

	ret = 0;
out:
	if (files_stmt)
		sqlite3_finalize(files_stmt);
	if (hashes_stmt)
		sqlite3_finalize(hashes_stmt);

	return ret;
}

/*
 * Scan files based on db contents:
 *
 *  1) Files in the db which don't yet have filerecs will be stat'd and added
 *
 *  2) Deleted files have their file and hash records removed
 *
 * The real work of step 1 happens in add_file_db()
 *
 * Step 2 happens at this time because it allows us to clean the
 * database of any unused inode / subvol pairs before we start
 * inserting stuff during the csum stage. This keeps us from getting
 * into a situation where we've inserted duplicate file records.
 */
int dbfile_scan_files(void)
{
	int ret;
	sqlite3 *db;
	LIST_HEAD(orphans);

	db = dbfile_get_handle();
	if (!db)
		return ENOENT;

	ret = dbfile_load_files(db, &orphans);
	if (ret)
		goto out;

	ret = dbfile_del_orphans(db, &orphans);

out:
	if (!list_empty(&orphans))
		free_orphan_list(&orphans);

	return ret;
}

static int dbfile_load_one_filerec(sqlite3 *db, uint64_t ino, uint64_t subvol,
				   struct filerec **file)
{
	int ret;
	sqlite3_stmt *stmt = NULL;
	const unsigned char *filename;
	uint64_t size;
	uint64_t mtime;
	unsigned int seq;

	*file = NULL;

#define LOAD_FILEREC	"select filename, size, mtime, dedupe_seq from files " \
			"where ino = ?1 and subvol = ?2;"

	ret = sqlite3_prepare_v2(db, LOAD_FILEREC, -1, &stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing statement");
		return ret;
	}

	ret = sqlite3_bind_int64(stmt, 1, ino);
	if (ret) {
		perror_sqlite(ret, "binding ino");
		goto out;
	}
	ret = sqlite3_bind_int64(stmt, 2, subvol);
	if (ret) {
		perror_sqlite(ret, "binding subvol");
		goto out;
	}

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_ROW) {
		perror_sqlite(ret, "executing statement");
		goto out;
	}
	ret = 0;

	filename = sqlite3_column_text(stmt, 0);
	size = sqlite3_column_int64(stmt, 1);
	mtime = sqlite3_column_int64(stmt, 2);
	seq = sqlite3_column_int(stmt, 3);

	*file = filerec_new((const char *)filename, ino, subvol, size, mtime);
	if (!*file)
		ret = ENOMEM;
	(*file)->dedupe_seq = seq;

out:
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
			ret = dbfile_load_one_filerec(db, ino, subvol, &file);
			if (ret) {
				fprintf(stderr, "Error loading filerec (%"
					PRIu64",%"PRIu64") from db\n",
					ino, subvol);
				goto out;
			}
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

	sort_file_hash_heads(hash_tree);

	ret = 0;
out:
	if (stmt)
		sqlite3_finalize(stmt);

	return ret;
}

static int iter_cb(void *priv, int argc, char **argv, char **column)
{
	iter_files_func func = priv;

	abort_on(argc != 3);
	func(argv[0], argv[1], argv[2]);
	return 0;
}

int dbfile_iter_files(sqlite3 *db, iter_files_func func)
{
	int ret;

#define	LIST_FILES	"select filename, ino, subvol from files;"
	ret = sqlite3_exec(db, LIST_FILES, iter_cb, func, NULL);
	if (ret) {
		perror_sqlite(ret, "Running sql to list files.");
		return ret;
	}

	return 0;
}

int dbfile_remove_file(sqlite3 *db, const char *filename)
{
	int ret;
	sqlite3_stmt *stmt = NULL;
	uint64_t ino, subvol;
	LIST_HEAD(orphans);
	struct orphan_file *o = NULL;

#define	ONE_FILE_INFO	"select ino, subvol from files where filename = ?1;"
	ret = sqlite3_prepare_v2(db, ONE_FILE_INFO, -1, &stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing files statement");
		goto out;
	}

	ret = sqlite3_bind_text(stmt, 1, filename, -1, SQLITE_TRANSIENT);
	if (ret) {
		perror_sqlite(ret, "binding filename for sql");
		goto out;
	}

	ret = sqlite3_step(stmt);
	if (ret == SQLITE_DONE) {
		ret = ENOENT;
		goto out;
	}
	if (ret != SQLITE_ROW) {
		perror_sqlite(ret, "finding file to remove");
		goto out;
	}

	ino = sqlite3_column_int64(stmt, 0);
	subvol = sqlite3_column_int64(stmt, 1);

	o = alloc_orphan_file(filename, ino, subvol);
	if (!o) {
		ret = ENOMEM;
		goto out;
	}
	list_add(&o->list, &orphans);

	ret = dbfile_del_orphans(db, &orphans);

out:
	free_orphan_list(&orphans);

	if (stmt)
		sqlite3_finalize(stmt);

	return ret;
}
