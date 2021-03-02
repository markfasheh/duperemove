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
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>

#include "csum.h"
#include "filerec.h"
#include "hash-tree.h"
#include "results-tree.h"
#include "file_scan.h"
#include "debug.h"

#include "dbfile.h"

/* exported for hashstats.c */
sqlite3 *gdb = NULL;

#if (SQLITE_VERSION_NUMBER < 3007015)
#define	perror_sqlite(_err, _why)					\
	fprintf(stderr, "%s(): Database error %d while %s: %s\n",	\
		__FUNCTION__, _err, _why, "[sqlite3_errstr() unavailable]")
#else
#define	perror_sqlite(_err, _why)					\
	fprintf(stderr, "%s()/%ld: Database error %d while %s: %s\n",	\
		__FUNCTION__, syscall(SYS_gettid), _err, _why, sqlite3_errstr(_err))
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
			       unsigned int *db_dedupe_seq,
			       unsigned int *extent_hash_src);

static void dbfile_config_defaults(struct dbfile_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	cfg->blocksize = blocksize;
	strncpy(cfg->hash_type, hash_type, 8);
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

static int create_tables(sqlite3 *db, int requested_version)
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

	switch (requested_version) {
	case DB_FILE_MAJOR:
#define	CREATE_TABLE_EXTENTS						\
"CREATE TABLE extents(digest BLOB KEY NOT NULL, ino INTEGER, subvol INTEGER, loff INTEGER, poff INTEGER, len INTEGER, flags INTEGER);"
		ret = sqlite3_exec(db, CREATE_TABLE_EXTENTS, NULL, NULL, NULL);
		if (ret)
			goto out;
		/* Fall through */
	case BLOCK_DEDUPE_DBFILE_VER:
#define	CREATE_TABLE_HASHES					\
"CREATE TABLE hashes(digest BLOB KEY NOT NULL, ino INTEGER, subvol INTEGER, loff INTEGER, flags INTEGER);"
		ret = sqlite3_exec(db, CREATE_TABLE_HASHES, NULL, NULL, NULL);
		break;
	default:
		ret = -EINVAL;
		break;
	}

out:
	return ret;
}

int create_indexes_old(sqlite3 *db)
{
	int ret;

#define	CREATE_HASHES_DIGEST_INDEX_OLD				\
"create index if not exists idx_digest on hashes(digest);"
	ret = sqlite3_exec(db, CREATE_HASHES_DIGEST_INDEX_OLD, NULL, NULL, NULL);
	if (ret)
		goto out;

#define	CREATE_HASHES_INOSUB_INDEX_OLD				\
"create index if not exists idx_hashes_inosub on hashes(ino, subvol);"
	ret = sqlite3_exec(db, CREATE_HASHES_INOSUB_INDEX_OLD, NULL, NULL, NULL);
	if (ret)
		goto out;

#define	CREATE_FILES_INOSUB_INDEX_OLD				\
"create index if not exists idx_inosub on files(ino, subvol);"
	ret = sqlite3_exec(db, CREATE_FILES_INOSUB_INDEX_OLD, NULL, NULL, NULL);
out:
	return ret;
}

int create_indexes(sqlite3 *db, struct dbfile_config *cfg)
{
	int ret;

	if (cfg->major == BLOCK_DEDUPE_DBFILE_VER) {
		ret = create_indexes_old(db);
		goto out;
	}

#define	CREATE_EXTENTS_DIGEST_INDEX					\
"create index if not exists idx_extent_digest on extents(digest);"
	ret = sqlite3_exec(db, CREATE_EXTENTS_DIGEST_INDEX, NULL, NULL, NULL);
	if (ret)
		goto out;

#define	CREATE_EXTENTS_INOSUB_INDEX					\
"create index if not exists idx_extents_inosub on extents(ino, subvol);"
	ret = sqlite3_exec(db, CREATE_EXTENTS_INOSUB_INDEX, NULL, NULL, NULL);
	if (ret)
		goto out;

#define	CREATE_FILES_INOSUB_INDEX					\
"create index if not exists idx_files_inosub on files(ino, subvol);"
	ret = sqlite3_exec(db, CREATE_FILES_INOSUB_INDEX, NULL, NULL, NULL);
	if (ret)
		goto out;

	ret = sqlite3_exec(db, CREATE_HASHES_DIGEST_INDEX_OLD, NULL, NULL, NULL);
	if (ret)
		goto out;

	ret = sqlite3_exec(db, CREATE_HASHES_INOSUB_INDEX_OLD, NULL, NULL, NULL);

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
#define MEMDB_FILENAME	"file::memory:?cache=shared"

int dbfile_create(char *filename, int *dbfile_is_new, int requested_version,
		  struct dbfile_config *cfg)
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
		filename = MEMDB_FILENAME;
	} else {
		ret = access(filename, R_OK|W_OK);
		if (ret == -1 && errno == ENOENT)
			newfile = 1;
	}

reopen:
#define OPEN_FLAGS	(SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_NOMUTEX|SQLITE_OPEN_URI)
	ret = sqlite3_open_v2(filename, &db, OPEN_FLAGS, NULL);
	if (ret) {
		perror_sqlite_open(db, filename);
		return ret;
	}

	if (newfile || inmem) {
		ret = create_tables(db, requested_version);
		if (ret) {
			perror_sqlite(ret, "creating tables");
			sqlite3_close(db);
			return ret;
		}
		/* Config is not written yet, but we can load some defaults. */
		dbfile_config_defaults(cfg);
		cfg->major = requested_version;
		cfg->minor = requested_version == DB_FILE_MAJOR ? DB_FILE_MINOR : 0;
		if (!inmem) {
			ret = chmod(filename, S_IRUSR|S_IWUSR);
			if (ret) {
				perror("setting db file permissions");
				sqlite3_close(db);
				return ret;
			}

		}
	} else {
		/* Get only version numbers initially */
		ret = __dbfile_get_config(db, NULL, NULL, NULL, NULL, NULL,
					  &vmajor, &vminor, NULL, NULL, NULL);
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

		if (vmajor != BLOCK_DEDUPE_DBFILE_VER &&
		    vmajor != DB_FILE_MAJOR) {
			fprintf(stderr, "Error: Hashfile \"%s\" has unknown "
				"version, %d.%d (I understand %d.%d)\n",
				filename, vmajor, vminor, DB_FILE_MAJOR,
				DB_FILE_MINOR);
			sqlite3_close(db);
			return -EIO;
		}

		ret = dbfile_get_config(db, cfg);
		if (ret) {
			perror_sqlite(ret, "loading dbfile config");
			return ret;
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

struct sqlite3 *dbfile_open_handle(char *filename)
{
	int ret;
	sqlite3 *db;

	if (!filename)
		filename = MEMDB_FILENAME;

	ret = sqlite3_open_v2(filename, &db, OPEN_FLAGS, NULL);
	if (ret) {
		perror_sqlite_open(db, filename);
		sqlite3_close(db);
		return NULL;
	}

	ret = dbfile_set_modes(db);
	if (ret) {
		perror_sqlite(ret, "setting journal modes");
		sqlite3_close(db);
		return NULL;
	}

	return db;
}

void dbfile_close_handle(struct sqlite3 *db)
{
	sqlite3_close(db);
}

int dbfile_open(char *filename, struct dbfile_config *cfg)
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

	dbfile_config_defaults(cfg);
	ret = dbfile_get_config(db, cfg);
	if (ret) {
		perror_sqlite(ret, "loading config");
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

int __dbfile_sync_config(sqlite3 *db, struct dbfile_config *cfg)
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

	ret = sync_config_text(stmt, "hash_type", cfg->hash_type, 8);
	if (ret)
		goto out;

	ret = sync_config_int(stmt, "extent_hash_src", cfg->extent_hash_src);
	if (ret)
		goto out;

	ret = sync_config_int(stmt, "block_size", cfg->blocksize);
	if (ret)
		goto out;

	onefs_major = major(cfg->onefs_dev);
	ret = sync_config_int(stmt, "onefs_dev_major", onefs_major);
	if (ret)
		goto out;

	onefs_minor = minor(cfg->onefs_dev);
	ret = sync_config_int(stmt, "onefs_dev_minor", onefs_minor);
	if (ret)
		goto out;

	ret = sync_config_int64(stmt, "onefs_fsid", cfg->onefs_fsid);
	if (ret)
		goto out;

	ret = sync_config_int(stmt, "dedupe_sequence", cfg->dedupe_seq);
	if (ret)
		goto out;

	ret = sync_config_int(stmt, "version_minor", cfg->minor);
	if (ret)
		goto out;

	/*
	 * Always write version_major last so we have an easy check
	 * whether the config table was fully written.
	 */
	ret = sync_config_int(stmt, "version_major", cfg->major);
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

int dbfile_sync_config(struct dbfile_config *cfg)
{
	sqlite3 *db;
	int ret;

	db = dbfile_get_handle();
	if (!db)
		return ENOENT;

	ret = __dbfile_sync_config(db, cfg);

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

static int dbfile_count_rows_old(sqlite3 *db, uint64_t *num_hashes,
				 uint64_t *num_files)
{
	int ret = 0;
	sqlite3_stmt *stmt = NULL;

	if (num_hashes) {
#define COUNT_HASHES_OLD "select COUNT(*) from hashes;"
		ret = sqlite3_prepare_v2(db, COUNT_HASHES_OLD, -1, &stmt, NULL);
		if (ret)
			goto out;

		ret = __dbfile_count_rows(stmt, num_hashes);
		if (ret)
			goto out;

		sqlite3_finalize(stmt);
		stmt = NULL;
	}

	if (num_files) {
#define COUNT_FILES_OLD "select COUNT(*) from files;"
		ret = sqlite3_prepare_v2(db, COUNT_FILES_OLD, -1, &stmt, NULL);
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

static int dbfile_count_rows_new(sqlite3 *db, uint64_t *num_hashes,
				 uint64_t *num_files)
{
	int ret = 0;
	sqlite3_stmt *stmt = NULL;

	if (num_hashes) {
#define COUNT_HASHES "select COUNT(*) from extents;"
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

static int dbfile_count_rows(sqlite3 *db, unsigned int ver,
			     uint64_t *num_hashes, uint64_t *num_files)
{
	if (ver == BLOCK_DEDUPE_DBFILE_VER)
		return dbfile_count_rows_old(db, num_hashes, num_files);
	else
		return dbfile_count_rows_new(db, num_hashes, num_files);
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
			       int *ret_ver_major, int *ver_minor,
			       char *db_hash_type, unsigned int *db_dedupe_seq,
			       unsigned int *extent_hash_src)
{
	int ret;
	sqlite3_stmt *stmt = NULL;
	unsigned int onefs_major, onefs_minor;
	int ver_major; /* We always query this */

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

	ret = get_config_int(stmt, "version_major", &ver_major);
	if (ret)
		goto out;
	if (ret_ver_major)
		*ret_ver_major = ver_major;

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

	if (ver_major > BLOCK_DEDUPE_DBFILE_VER) {
		ret = get_config_int(stmt, "extent_hash_src",
				     (int *)extent_hash_src);
		if (ret)
			goto out;
	} else 	if (extent_hash_src) {
		*extent_hash_src = 0;
	}

	sqlite3_finalize(stmt);
	stmt = NULL;

	ret = dbfile_count_rows(db, ver_major, num_hashes, num_files);
	if (ret)
		goto out;

out:
	if (stmt)
		sqlite3_finalize(stmt);
	return ret;
}

int dbfile_get_config(sqlite3 *db, struct dbfile_config *cfg)
{
	int ret;

	ret = __dbfile_get_config(db, &cfg->blocksize, &cfg->num_hashes,
				  &cfg->num_files, &cfg->onefs_dev,
				  &cfg->onefs_fsid, &cfg->major,
				  &cfg->minor, cfg->hash_type,
				  &cfg->dedupe_seq, &cfg->extent_hash_src);

	return ret;
}

static int dbfile_check_version(sqlite3 *db)
{
	int ret;
	int ver_major, ver_minor;

	ret = __dbfile_get_config(db, NULL, NULL, NULL, NULL, NULL, &ver_major,
				  &ver_minor, NULL, NULL, NULL);
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

static int __dbfile_store_file_info(sqlite3 *db, sqlite3_stmt *stmt,
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

int dbfile_store_file_info(sqlite3 *db, struct filerec *file)
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

	ret = __dbfile_store_file_info(db, stmt, file);

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

			ret = __dbfile_store_file_info(db, stmt, file);
			if (ret)
				break;

			file->flags &= ~FILEREC_UPDATE_DB;
			sqlite3_reset(stmt);
		}
	}

	sqlite3_finalize(stmt);

	return ret;
}

static int __dbfile_remove_file_hashes(sqlite3_stmt *hashes_stmt,
				       sqlite3_stmt *extents_stmt, uint64_t ino,
				       uint64_t subvol)
{
	int ret;
	sqlite3_stmt *stmt = hashes_stmt;
	bool done = false;
	const char *errstr = "executing hashes statement";

again:
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
		perror_sqlite(ret, errstr);
		goto out;
	}
	if (!done && extents_stmt) {
		stmt = extents_stmt;
		errstr = "executing extents statement";
		done = true;
		goto again;
	}
	ret = 0;
out:
	return ret;
}

static int remove_file_hashes_prep(sqlite3 *db, struct dbfile_config *cfg,
				   sqlite3_stmt **hashes_stmt,
				   sqlite3_stmt **extents_stmt)
{
	int ret;

	*hashes_stmt = *extents_stmt = NULL;

#define	REMOVE_FILE_HASHES					\
	"delete from hashes where ino = ?1 and subvol = ?2;"
	ret = sqlite3_prepare_v2(db, REMOVE_FILE_HASHES, -1,
				 hashes_stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing hash insert statement");
		return ret;
	}
	if (cfg->major > BLOCK_DEDUPE_DBFILE_VER) {
#define	REMOVE_EXTENT_HASHES					\
	"delete from extents where ino = ?1 and subvol = ?2;"
		ret = sqlite3_prepare_v2(db, REMOVE_EXTENT_HASHES, -1,
					 extents_stmt, NULL);
		if (ret)
			perror_sqlite(ret, "preparing hash insert statement");
		return ret;
	}
	return 0;
}

static int dbfile_remove_file_hashes(sqlite3 *db, struct dbfile_config *cfg,
				     struct filerec *file)
{
	int ret;
	sqlite3_stmt *hashes_stmt = NULL;
	sqlite3_stmt *extents_stmt = NULL;

	ret = remove_file_hashes_prep(db, cfg, &hashes_stmt, &extents_stmt);
	if (ret) {
		perror_sqlite(ret, "preparing file hash removal statement");
		return ret;
	}

	ret = __dbfile_remove_file_hashes(hashes_stmt, extents_stmt, file->inum,
					  file->subvolid);

	return ret;
}

int dbfile_store_block_hashes(sqlite3 *db, struct dbfile_config *cfg,
			      struct filerec *file, uint64_t nb_hash,
			      struct block_csum *hashes)
{
	int ret;
	uint64_t i;
	sqlite3_stmt *stmt = NULL;
	uint64_t loff;
	uint32_t flags;
	unsigned char *digest;

	if (file->flags & FILEREC_IN_DB) {
		ret = dbfile_remove_file_hashes(db, cfg, file);
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

int dbfile_store_extent_hashes(sqlite3 *db, struct dbfile_config *cfg,
			       struct filerec *file, uint64_t nb_hash,
			       struct extent_csum *hashes)
{
	int ret;
	uint64_t i;
	sqlite3_stmt *stmt = NULL;
	uint64_t loff, poff;
	uint32_t flags, len;
	unsigned char *digest;

	if (file->flags & FILEREC_IN_DB) {
		ret = dbfile_remove_file_hashes(db, cfg, file);
		if (ret)
			return ret;
	}

	dprintf("db: write %d hashes for file %s\n", (int)nb_hash,
		file->filename);
#define	UPDATE_EXTENTS						\
"INSERT INTO extents (ino, subvol, loff, poff, len, flags, digest) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);"
	ret = sqlite3_prepare_v2(db, UPDATE_EXTENTS, -1, &stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing extents insert statement");
		goto out_error;
	}

	for (i = 0; i < nb_hash; i++) {
		loff = hashes[i].loff;
		poff = hashes[i].poff;
		len = hashes[i].len;
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

		ret = sqlite3_bind_int64(stmt, 4, poff);
		if (ret)
			goto bind_error;

		/*
		 * XXX: Should len really be u64? I think fiemap uses
		 * 32 bits here
		 */
		ret = sqlite3_bind_int(stmt, 5, len);
		if (ret)
			goto bind_error;

		ret = sqlite3_bind_int(stmt, 6, flags);
		if (ret)
			goto bind_error;

		ret = sqlite3_bind_blob(stmt, 7, digest, digest_len,
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
	int len = strlen(filename) + 1;
	struct orphan_file *o = calloc(1, sizeof(*o) + len);

	if (o) {
		o->filename = o->buf;
		strcpy(o->filename, filename);
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

static int dbfile_del_orphans(struct sqlite3 *db, struct dbfile_config *cfg,
			      struct list_head *orphans)
{
	int ret;
	sqlite3_stmt *files_stmt = NULL;
	sqlite3_stmt *hashes_stmt = NULL;
	sqlite3_stmt *extents_stmt = NULL;
	struct orphan_file *o, *tmp;

#define	DELETE_FILE	"delete from files where filename = ?1;"
	ret = sqlite3_prepare_v2(db, DELETE_FILE, -1, &files_stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing files statement");
		goto out;
	}

	ret = remove_file_hashes_prep(db, cfg, &hashes_stmt, &extents_stmt);
	if (ret) {
		perror_sqlite(ret, "preparing hashes statement");
		goto out;
	}

	list_for_each_entry_safe(o, tmp, orphans, list) {
		dprintf("Remove file \"%s\" from the db\n",
			o->filename);

		ret = __dbfile_remove_file_hashes(hashes_stmt, extents_stmt,
						  o->ino, o->subvol);
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
		sqlite3_reset(extents_stmt);
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
	if (extents_stmt)
		sqlite3_finalize(extents_stmt);

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
int dbfile_scan_files(struct dbfile_config *cfg)
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

	ret = dbfile_del_orphans(db, cfg, &orphans);

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

int dbfile_load_block_hashes(struct hash_tree *hash_tree)
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

int dbfile_load_extent_hashes(struct results_tree *res)
{
	int ret, flags;
	sqlite3 *db;
	sqlite3_stmt *stmt = NULL;
	uint64_t subvol, ino, loff, poff;
	unsigned int len;
	unsigned char *digest;
	struct filerec *file;

	db = dbfile_get_handle();
	if (!db)
		return ENOENT;

	ret = dbfile_check_version(db);
	if (ret)
		return ret;

	/*
	 * We need to select on both digest and len, otherwise we
	 * could run into a situation where a single extent with a
	 * colliding hash but different length gets placed into the
	 * results tree, which will get very angry when it has a
	 * result of only one extent.
	 */
#define GET_DUPLICATE_EXTENTS					      \
	"SELECT extents.digest, ino, subvol, loff, extents.len, poff, flags FROM extents " \
	"JOIN (SELECT digest,len FROM extents GROUP BY digest,len HAVING count(*) > 1) " \
	"AS duplicate_extents on extents.digest = duplicate_extents.digest AND " \
	"extents.len = duplicate_extents.len;"

	ret = sqlite3_prepare_v2(db, GET_DUPLICATE_EXTENTS, -1, &stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing statement");
		return ret;
	}

	while ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {
		digest = (unsigned char *)sqlite3_column_blob(stmt, 0);
		ino = sqlite3_column_int64(stmt, 1);
		subvol = sqlite3_column_int64(stmt, 2);
		loff = sqlite3_column_int64(stmt, 3);
		len = sqlite3_column_int(stmt, 4);
		poff = sqlite3_column_int64(stmt, 5);
		flags = sqlite3_column_int(stmt, 6);

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

		ret = insert_one_result(res, digest, file, loff, len, poff, flags);
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

int dbfile_load_one_file_extent(sqlite3 *db, struct filerec *file,
				uint64_t loff, unsigned int len,
				struct file_extent *extent)
{
	int ret;
	sqlite3_stmt *stmt = NULL;

#define GET_FILE_EXTENT	"select poff, loff, len, flags from extents where " \
	"ino = ?1 and subvol = ?2 and loff <= ?3 and (loff + len) > ?3;"
	ret = sqlite3_prepare_v2(db, GET_FILE_EXTENT, -1, &stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing get file extents statement");
		goto out;
	}

	ret = sqlite3_bind_int64(stmt, 1, file->inum);
	if (ret)
		goto out;

	ret = sqlite3_bind_int64(stmt, 2, file->subvolid);
	if (ret)
		goto out;

	ret = sqlite3_bind_int64(stmt, 3, loff);
	if (ret)
		goto out;

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_ROW) {
		perror_sqlite(ret, "retrieving extent info");
		return ret;
	}

	extent->poff = sqlite3_column_int64(stmt, 0);
	extent->loff = sqlite3_column_int64(stmt, 1);
	extent->len = sqlite3_column_int64(stmt, 2);
	extent->flags = sqlite3_column_int(stmt, 3);

	ret = 0;
out:
	sqlite3_finalize(stmt);
	return ret;
}

int dbfile_load_nondupe_file_extents(sqlite3 *db, struct filerec *file,
				     struct file_extent **ret_extents,
				     unsigned int *num_extents)
{
	int ret, i;
	sqlite3_stmt *stmt = NULL;
	uint64_t count;
	struct file_extent *extents = NULL;

#define NONDUPE_JOIN							\
	"FROM extents JOIN (SELECT digest FROM extents GROUP BY digest "\
	"HAVING count(*) = 1) AS nondupe_extents on extents.digest = "	\
	"nondupe_extents.digest where extents.ino = ?1 and extents.subvol = ?2;"
#define GET_NONDUPE_EXTENTS						\
	"select extents.loff, len, poff, flags " NONDUPE_JOIN
#define GET_NONDUPE_EXTENTS_COUNT					\
	"select COUNT(*) " NONDUPE_JOIN

	ret = sqlite3_prepare_v2(db, GET_NONDUPE_EXTENTS_COUNT, -1, &stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing get file extents statement");
		goto out;
	}

	ret = sqlite3_bind_int64(stmt, 1, file->inum);
	if (ret)
		goto out;

	ret = sqlite3_bind_int64(stmt, 2, file->subvolid);
	if (ret)
		goto out;

	ret = __dbfile_count_rows(stmt, &count);
	if (ret)
		goto out;

	sqlite3_finalize(stmt);
	stmt = NULL;

	if (count > UINT32_MAX) {
		fprintf(stderr, "File \"%s\" has %"PRIu64" extents.\n",
			file->filename, count);
		count = UINT32_MAX;
	}
	*num_extents = count;

	extents = calloc(count, sizeof(struct file_extent));
	if (!extents) {
		ret = ENOMEM;
		goto out;
	}

	ret = sqlite3_prepare_v2(db, GET_NONDUPE_EXTENTS, -1, &stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing nondupe extents statement");
		goto out;
	}

	ret = sqlite3_bind_int64(stmt, 1, file->inum);
	if (ret)
		goto out;

	ret = sqlite3_bind_int64(stmt, 2, file->subvolid);
	if (ret)
		goto out;

	i = 0;
	while ((ret = sqlite3_step(stmt)) == SQLITE_ROW && i < count) {
		extents[i].loff = sqlite3_column_int64(stmt, 0);
		extents[i].len = sqlite3_column_int64(stmt, 1);
		extents[i].poff = sqlite3_column_int64(stmt, 2);
		extents[i].flags = sqlite3_column_int(stmt, 3);

		++i;
	}
	if (ret != SQLITE_DONE) {
		perror_sqlite(ret, "stepping nondupe extents statement");
		goto out;
	}
	*ret_extents = extents;
	ret = 0;
out:
	if (ret && extents)
		free(extents);
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

int dbfile_remove_file(sqlite3 *db, struct dbfile_config *cfg,
		       const char *filename)
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

	ret = dbfile_del_orphans(db, cfg, &orphans);

out:
	free_orphan_list(&orphans);

	if (stmt)
		sqlite3_finalize(stmt);

	return ret;
}
