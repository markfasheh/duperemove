#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sqlite3.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdbool.h>
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
#include "opt.h"

static struct dbhandle *gdb = NULL;

static sqlite3 *__dbfile_open_handle(char *filename, bool force_create);

static GMutex io_mutex; /* Locks db writes */

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

struct dbhandle *dbfile_get_handle(void)
{
	return gdb;
}

void dbfile_lock()
{
	g_mutex_lock(&io_mutex);
}

void dbfile_unlock()
{
	g_mutex_unlock(&io_mutex);
}

static void dbfile_config_defaults(struct dbfile_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	cfg->blocksize = blocksize;
	memcpy(cfg->hash_type, HASH_TYPE, 8);

	cfg->major = DB_FILE_MAJOR;
	cfg->minor = DB_FILE_MINOR;

	cfg->blocksize = blocksize;
}

static int dbfile_get_dbpath(sqlite3 *db, char *path)
{
	int ret;
	_cleanup_(sqlite3_stmt_cleanup) sqlite3_stmt *stmt = NULL;
	const char *buf;

#define GET_DBPATH "select file from pragma_database_list where name = 'main' limit 1;"
	ret = sqlite3_prepare_v2(db, GET_DBPATH, -1, &stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing statement");
		return ret;
	}

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_ROW) {
		perror_sqlite(ret, "fetching database's backend path");
		return ret;
	}

	buf = (char *)sqlite3_column_text(stmt, 0);
	if (strnlen(buf, PATH_MAX) != 0) {
		strncpy(path, buf, PATH_MAX);
	} else {
		strcpy(path, "(null)");
	}

	return 0;
}

static int dbfile_check(sqlite3 *db, struct dbfile_config *cfg)
{
	char path[PATH_MAX + 1];

	if (cfg->major != DB_FILE_MAJOR || cfg->minor != DB_FILE_MINOR) {
		fprintf(stderr,
			"Hash db version mismatch (mine: %d.%d, file: %d.%d)\n",
			DB_FILE_MAJOR, DB_FILE_MINOR, cfg->major, cfg->minor);
		return EIO;
	}

	dbfile_get_dbpath(db, path);

	if (strncasecmp(cfg->hash_type, HASH_TYPE, 8)) {
		fprintf(stderr,
			"Error: Hashfile %s uses \"%.*s\" for checksums "
			"but we are using %.*s.\nYou are probably "
			"using a hashfile generated from an old version, "
			"which cannot be read anymore.\n", path, 8,
			cfg->hash_type, 8, HASH_TYPE);
		return EINVAL;
	}

	if (cfg->blocksize != blocksize) {
		vprintf("Using blocksize %uK from hashfile (%uK "
			"blocksize requested).\n", cfg->blocksize/1024,
			blocksize/1024);
		blocksize = cfg->blocksize;
	}

	return 0;
}

static int create_tables(sqlite3 *db)
{
	int ret;

#define CREATE_TABLE_CONFIG						\
"CREATE TABLE IF NOT EXISTS config(keyname TEXT PRIMARY KEY NOT NULL, "	\
"keyval BLOB, UNIQUE(keyname));"
	ret = sqlite3_exec(db, CREATE_TABLE_CONFIG, NULL, NULL, NULL);
	if (ret)
		goto out;

#define	CREATE_TABLE_FILES						\
"CREATE TABLE IF NOT EXISTS files(id INTEGER PRIMARY KEY NOT NULL, "	\
"filename TEXT NOT NULL, "						\
"ino INTEGER, subvol INTEGER, size INTEGER, blocks INTEGER, "		\
"mtime INTEGER, dedupe_seq INTEGER, digest BLOB, "			\
"flags INTEGER, UNIQUE(ino, subvol), UNIQUE(filename));"
	ret = sqlite3_exec(db, CREATE_TABLE_FILES, NULL, NULL, NULL);
	if (ret)
		goto out;

#define	CREATE_TABLE_EXTENTS						\
"CREATE TABLE IF NOT EXISTS extents(digest BLOB KEY NOT NULL, "		\
"fileid INTEGER, loff INTEGER, poff INTEGER, len INTEGER, "		\
"UNIQUE(fileid, loff, len) "						\
"FOREIGN KEY(fileid) REFERENCES files(id) ON DELETE CASCADE);"
	ret = sqlite3_exec(db, CREATE_TABLE_EXTENTS, NULL, NULL, NULL);
	if (ret)
		goto out;

#define	CREATE_TABLE_BLOCKS						\
"CREATE TABLE IF NOT EXISTS blocks(digest BLOB KEY NOT NULL, "		\
"fileid INTEGER, loff INTEGER, "					\
"UNIQUE(fileid, loff) "							\
"FOREIGN KEY(fileid) REFERENCES files(id) ON DELETE CASCADE);"
	ret = sqlite3_exec(db, CREATE_TABLE_BLOCKS, NULL, NULL, NULL);

out:
	if (ret)
		perror_sqlite(ret, "creating database tables");

	return ret;
}

static int create_indexes(sqlite3 *db)
{
	int ret;

#define	CREATE_BLOCKS_DIGEST_INDEX					\
"create index if not exists idx_digest on blocks(digest);"
	ret = sqlite3_exec(db, CREATE_BLOCKS_DIGEST_INDEX, NULL, NULL, NULL);
	if (ret)
		goto out;

#define	CREATE_BLOCKS_INOSUB_INDEX					\
"create index if not exists idx_blocks_inosub on blocks(fileid);"
	ret = sqlite3_exec(db, CREATE_BLOCKS_INOSUB_INDEX, NULL, NULL, NULL);
	if (ret)
		goto out;

#define	CREATE_EXTENTS_DIGEST_INDEX					\
"create index if not exists idx_extent_digest on extents(digest);"
	ret = sqlite3_exec(db, CREATE_EXTENTS_DIGEST_INDEX, NULL, NULL, NULL);
	if (ret)
		goto out;

#define CREATE_EXTENTS_FILEID_INDEX					\
"create index if not exists idx_extents_inosub on extents(fileid);"
	ret = sqlite3_exec(db, CREATE_EXTENTS_FILEID_INDEX, NULL, NULL, NULL);
	if (ret)
		goto out;

#define	CREATE_FILES_INOSUB_INDEX					\
"create index if not exists idx_files_inosub on files(ino, subvol);"
	ret = sqlite3_exec(db, CREATE_FILES_INOSUB_INDEX, NULL, NULL, NULL);
	if (ret)
		goto out;

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

	ret = sqlite3_exec(db, "PRAGMA journal_mode = WAL", NULL, NULL, NULL);
	if (ret) {
		perror_sqlite(ret, "configuring database (journal mode)");
		return ret;
	}

	ret = sqlite3_exec(db, "PRAGMA cache_size = -256000", NULL, NULL, NULL);
	if (ret) {
		perror_sqlite(ret, "configuring database (cache size)");
		return ret;
	}

	ret = sqlite3_exec(db, "PRAGMA foreign_keys = ON", NULL, NULL, NULL);
	if (ret) {
		perror_sqlite(ret, "enabling foreign keys");
		return ret;
	}

	return ret;
}

static int dbfile_prepare(sqlite3 *db)
{
	struct dbfile_config cfg;
	int ret;
	char dbpath[PATH_MAX + 1];

	ret = create_tables(db);
	if (ret) {
		perror_sqlite(ret, "creating tables");
		return ret;
	}

	ret = create_indexes(db);
	if (ret) {
		perror_sqlite(ret, "creating indexes");
		return ret;
	}

	ret = dbfile_get_dbpath(db, dbpath);
	if (ret)
		return ret;

	if (strcmp("(null)", dbpath) != 0) {
		ret = chmod(dbpath, S_IRUSR|S_IWUSR);
		if (ret) {
			perror("setting db file permissions");
			return ret;
		}
	}

	ret = dbfile_get_config(db, &cfg);
	if (ret) {
		perror_sqlite(ret, "reading initial db config");
		return ret;
	}

	ret = dbfile_check(db, &cfg);
	if (ret && strcmp("(null)", dbpath) != 0) {
		fprintf(stderr, "Recreating hashfile ..\n");
		sqlite3_close(db);
		ret = unlink(dbpath);
		if ( ret && errno != ENOENT) {
			ret = errno;
			fprintf(stderr, "Error %d while unlinking old "
				"db file \"%s\" : %s\n", ret, dbpath,
				strerror(ret));
			return ret;
		}

		db = __dbfile_open_handle(dbpath, false);
		return dbfile_prepare(db);
	}

	/* May store the default config, if fields were missing
	 * or if the database did not exist
	 */
	ret = __dbfile_sync_config(db, &cfg);
	if (ret) {
		perror_sqlite(ret, "sync db config");
		return ret;
	}

	return 0;
}


#define MEMDB_FILENAME		"file::memory:?cache=shared"
#define OPEN_FLAGS		(SQLITE_OPEN_READWRITE|SQLITE_OPEN_NOMUTEX|SQLITE_OPEN_URI)
#define OPEN_FLAGS_CREATE	(OPEN_FLAGS|SQLITE_OPEN_CREATE)
static sqlite3 *__dbfile_open_handle(char *filename, bool force_create)
{
	int ret;
	sqlite3 *db;

	if (!filename) {
		filename = MEMDB_FILENAME;
		force_create = true;
	}

	if (force_create)
		ret = sqlite3_open_v2(filename, &db, OPEN_FLAGS_CREATE, NULL);
	else
		ret = sqlite3_open_v2(filename, &db, OPEN_FLAGS, NULL);

	if (ret == SQLITE_CANTOPEN && !force_create) {
		vprintf("Cannot open an existing hashfile, retrying in create mode\n");
		sqlite3_close(db);
		return __dbfile_open_handle(filename, true);
	}

	if (ret) {
		perror_sqlite_open(db, filename);
		sqlite3_close(db);
		return NULL;
	}

	ret = dbfile_set_modes(db);
	if (ret) {
		sqlite3_close(db);
		return NULL;
	}

	/* The handle is now created
	 * If force_create is true, then this is a new database, either
	 * on disk or in memory, which shall be initialized
	 */
	if (force_create) {
		ret = dbfile_prepare(db);
		if (ret) {
			sqlite3_close(db);
			return NULL;
		}
	}

	return db;
}

#define dbfile_prepare_stmt(member, query) do {							\
	int ret = sqlite3_prepare_v2(result->db, query, -1, &(result->stmts.member), NULL);	\
	if (ret) {										\
		perror_sqlite(ret, "preparing stmt");						\
		goto err;									\
	}											\
} while (0)

struct dbhandle *dbfile_open_handle(char *filename)
{
	struct dbhandle *result = calloc(1, sizeof(struct dbhandle));
	result->db = __dbfile_open_handle(filename, false);

	if (!result->db)
		goto err;

#define	INSERT_BLOCK							\
"INSERT INTO blocks (fileid, loff, digest) VALUES (?1, ?2, ?3);"
	dbfile_prepare_stmt(insert_block, INSERT_BLOCK);

#define	INSERT_EXTENTS							\
"INSERT INTO extents (fileid, loff, poff, len, digest) "		\
"VALUES (?1, ?2, ?3, ?4, ?5);"
	dbfile_prepare_stmt(insert_extent, INSERT_EXTENTS);

#define UPDATE_SCANNED_FILE						\
"UPDATE files SET digest = ?1, flags = ?2 where id = ?3;"
	dbfile_prepare_stmt(update_scanned_file, UPDATE_SCANNED_FILE);

#define FIND_BLOCKS                                                     \
"select files.filename, blocks.loff from files "			\
"INNER JOIN blocks "							\
"on blocks.digest = ?1 AND files.id = blocks.fileid;"
	dbfile_prepare_stmt(find_blocks, FIND_BLOCKS);

#define FIND_TOP_B_HASHES						\
"select digest, count(digest) from blocks "				\
"group by digest having (count(digest) > 1) "				\
"order by (count(digest)) desc;"
	dbfile_prepare_stmt(find_top_b_hashes, FIND_TOP_B_HASHES);

#define FIND_TOP_E_HASHES						\
"select digest, count(digest) from extents "				\
"group by digest having (count(digest) > 1) "				\
"order by (count(digest)) desc;"
	dbfile_prepare_stmt(find_top_e_hashes, FIND_TOP_E_HASHES);

#define FIND_B_FILES_COUNT						\
"select count (distinct files.filename) from files "			\
"INNER JOIN blocks "							\
"on blocks.digest = ?1 AND files.id = blocks.fileid;"
	dbfile_prepare_stmt(find_b_files_count, FIND_B_FILES_COUNT);

#define FIND_E_FILES_COUNT						\
"select count (distinct files.filename) from files "			\
"INNER JOIN extents on extents.digest = ?1 "				\
"AND files.id = extents.fileid;"
	dbfile_prepare_stmt(find_e_files_count, FIND_E_FILES_COUNT);

#define	UPDATE_EXTENT_POFF						\
"update extents set poff = ?1 "						\
"where fileid = (select id from files where ino = ?2 and subvol = ?3) "	\
"and loff = ?4;"
	dbfile_prepare_stmt(update_extent_poff, UPDATE_EXTENT_POFF);

#define	WRITE_FILE							\
"insert or replace into files (ino, subvol, filename, size, mtime, "	\
"dedupe_seq) VALUES (?1, ?2, ?3, ?4, ?5, ?6);"
	dbfile_prepare_stmt(write_file, WRITE_FILE);

#define REMOVE_BLOCK_HASHES						\
"delete from blocks where fileid = (select id from files "		\
"where ino = ?1 and subvol = ?2);"
	dbfile_prepare_stmt(remove_block_hashes, REMOVE_BLOCK_HASHES);

#define REMOVE_EXTENT_HASHES						\
"delete from extents where fileid = (select id from files "		\
"where ino = ?1 and subvol = ?2);"
	dbfile_prepare_stmt(remove_extent_hashes, REMOVE_EXTENT_HASHES);

#define LOAD_FILEREC							\
"select filename, size from files where ino = ?1 and subvol = ?2;"
	dbfile_prepare_stmt(load_filerec, LOAD_FILEREC);

#define GET_DUPLICATE_BLOCKS						\
"WITH without_future_blocks as ("					\
"	select * from blocks "						\
"	join files on files.id = blocks.fileid "			\
"	and files.dedupe_seq <= ?1), "					\
"current_blocks as ("							\
"	select * from blocks "						\
"	join files on files.id = blocks.fileid "			\
"	and files.dedupe_seq = ?1) "					\
"SELECT without_future_blocks.digest, ino, subvol, loff "		\
"FROM without_future_blocks "						\
"JOIN (SELECT DISTINCT digest FROM current_blocks "			\
"GROUP BY digest "							\
"HAVING count(*) > 1) AS duplicate_blocks "				\
"on without_future_blocks.digest = duplicate_blocks.digest;"
	dbfile_prepare_stmt(get_duplicate_blocks, GET_DUPLICATE_BLOCKS);

/*
 * We need to select on both digest and len, otherwise we
 * could run into a situation where a single extent with a
 * colliding hash but different length gets placed into the
 * results tree, which will get very angry when it has a
 * result of only one extent.
 */
#define GET_DUPLICATE_EXTENTS						\
"WITH without_future_extents as ("					\
"	select * from extents "						\
"	join files on files.id = extents.fileid "			\
"	and files.dedupe_seq <= ?1), "					\
"current_extents as ("							\
"	select * from extents "						\
"	join files on files.id = extents.fileid "			\
"	and files.dedupe_seq = ?1) "					\
"SELECT without_future_extents.digest, ino, subvol, loff, "		\
"without_future_extents.len, poff "					\
"FROM without_future_extents "						\
"JOIN (SELECT digest, len FROM current_extents "			\
"GROUP BY digest, len HAVING count(*) > 1) AS duplicate_extents "	\
"on without_future_extents.digest = duplicate_extents.digest "		\
"AND without_future_extents.len = duplicate_extents.len;"
	dbfile_prepare_stmt(get_duplicate_extents, GET_DUPLICATE_EXTENTS);

#define GET_DUPLICATE_FILES						\
"WITH without_future_files as ( "					\
"	select * from files where dedupe_seq <= ?1 "			\
"	and not (flags & 1)), "						\
"current_files as ( "							\
"	select * from files where dedupe_seq = ?1 "			\
"	and not (flags & 1)) "						\
"SELECT ino, subvol, without_future_files.size, "			\
"without_future_files.digest FROM without_future_files "		\
"JOIN (SELECT digest, size FROM current_files "				\
"GROUP BY digest, size HAVING count(*) > 1) "				\
"AS duplicate_files "							\
"ON without_future_files.digest = duplicate_files.digest "		\
"AND without_future_files.size = duplicate_files.size;"
	dbfile_prepare_stmt(get_duplicate_files, GET_DUPLICATE_FILES);

#define GET_FILE_EXTENT							\
"select poff, loff, len from extents "					\
"join files on files.id = extents.fileid "				\
"where ino = ?1 and subvol = ?2 and loff <= ?3 and (loff + len) > ?3;"
	dbfile_prepare_stmt(get_file_extent, GET_FILE_EXTENT);

#define GET_NONDUPE_EXTENTS						\
"select extents.loff, len, poff "					\
"FROM extents join files on files.id = extents.fileid "			\
"where files.ino = ?1 and files.subvol = ?2 and "			\
"(1 = (SELECT COUNT(*) FROM extents as e where e.digest = extents.digest));"
	dbfile_prepare_stmt(get_nondupe_extents, GET_NONDUPE_EXTENTS);

#define DELETE_FILE "delete from files where filename = ?1;"
	dbfile_prepare_stmt(delete_file, DELETE_FILE);

#define SELECT_FILE_CHANGES						\
"select mtime, size, filename from files where ino = ?1 and subvol = ?2;"
	dbfile_prepare_stmt(select_file_changes, SELECT_FILE_CHANGES);

#define COUNT_B_HASHES "select COUNT(*) from blocks;"
	dbfile_prepare_stmt(count_b_hashes, COUNT_B_HASHES);

#define COUNT_E_HASHES "select COUNT(*) from extents;"
	dbfile_prepare_stmt(count_e_hashes, COUNT_E_HASHES);

#define COUNT_FILES "select COUNT(*) from files;"
	dbfile_prepare_stmt(count_files, COUNT_FILES);

#define GET_MAX_DEDUPE_SEQ "select max(dedupe_seq) from files;"
	dbfile_prepare_stmt(get_max_dedupe_seq, GET_MAX_DEDUPE_SEQ);

#define DELETE_UNSCANNED_FILES "delete from files where digest is NULL;"
	dbfile_prepare_stmt(delete_unscanned_files, DELETE_UNSCANNED_FILES);

#define RENAME_FILE							\
"update files set filename = ?1 where ino = ?2 and subvol = ?3;"
	dbfile_prepare_stmt(rename_file, RENAME_FILE);
	return result;

err:
	dbfile_close_handle(result);
	return NULL;
}

void dbfile_close_handle(struct dbhandle *db)
{
	if(db) {
		/* struct stmts is a named array of sqlite3_stmt*
		 * let's iterate over all unnamed elements and
		 * finalize each of them
		 */
		sqlite3_stmt **stmts = (sqlite3_stmt**)&(db->stmts);

		int len = sizeof(struct stmts) / sizeof(sqlite3_stmt*);
		for (int i = 0; i < len; i++) {
			sqlite3_finalize(stmts[i]);
		}

		sqlite3_close(db->db);
		free(db);
	}
}

uint64_t count_file_by_digest(struct dbhandle *db, unsigned char *digest,
				bool show_block_hashes)
{
	int ret;
	_cleanup_(sqlite3_reset_stmt) sqlite3_stmt *stmt;

	if (show_block_hashes)
		stmt = db->stmts.find_b_files_count;
	else
		stmt = db->stmts.find_e_files_count;

	ret = sqlite3_bind_blob(stmt, 1, digest, DIGEST_LEN, SQLITE_STATIC);
	if (ret) {
		fprintf(stderr, "Error %d binding digest: %s\n", ret,
			sqlite3_errstr(ret));
		return 0;
	}

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_ROW && ret != SQLITE_DONE) {
		fprintf(stderr, "error %d, file count search: %s\n",
			ret, sqlite3_errstr(ret));
		return 0;
	}

	return sqlite3_column_int64(stmt, 0);
}

int dbfile_begin_trans(sqlite3 *db)
{
	int ret;

	ret = sqlite3_exec(db, "begin transaction", NULL, NULL, NULL);
	if (ret)
		perror_sqlite(ret, "starting transaction");
	return ret;
}

int dbfile_update_extent_poff(struct dbhandle *db, uint64_t ino, uint64_t subvol,
				uint64_t loff, uint64_t poff)
{
	int ret;
	_cleanup_(sqlite3_reset_stmt) sqlite3_stmt *stmt = db->stmts.update_extent_poff;

	ret = sqlite3_bind_int64(stmt, 1, poff);
	if (ret)
		goto bind_error;

	ret = sqlite3_bind_int64(stmt, 2, ino);
	if (ret)
		goto bind_error;

	ret = sqlite3_bind_int64(stmt, 3, subvol);
	if (ret)
		goto bind_error;

	ret = sqlite3_bind_int64(stmt, 4, loff);
	if (ret)
		goto bind_error;

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE) {
		perror_sqlite(ret, "executing statement");
		return ret;
	}

	ret = 0;
bind_error:
	if (ret)
		perror_sqlite(ret, "binding values");

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

int dbfile_abort_trans(sqlite3 *db)
{
	int ret;

	ret = sqlite3_exec(db, "rollback transaction", NULL, NULL, NULL);
	if (ret)
		perror_sqlite(ret, "aborting transaction");
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

int __dbfile_sync_config(sqlite3 *db, struct dbfile_config *cfg)
{
	int ret = 0;
	char uuid[37]; /* 36-bytes uuid + \0 */
	_cleanup_(sqlite3_stmt_cleanup) sqlite3_stmt *stmt = NULL;

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

	ret = sync_config_int(stmt, "block_size", cfg->blocksize);
	if (ret)
		goto out;

	ret = sync_config_int(stmt, "dedupe_sequence", cfg->dedupe_seq);
	if (ret)
		goto out;

	ret = sync_config_int(stmt, "version_minor", cfg->minor);
	if (ret)
		goto out;

	uuid_unparse(cfg->fs_uuid, uuid);
	ret = sync_config_text(stmt, "fs_uuid", uuid, 36);
	if (ret)
		goto out;

	/*
	 * Always write version_major last so we have an easy check
	 * whether the config table was fully written.
	 */
	ret = sync_config_int(stmt, "version_major", cfg->major);
	if (ret)
		goto out;

out:
	if (ret) {
		perror_sqlite(ret, "binding");
	}

	return ret;
}

int dbfile_sync_config(struct dbhandle *db, struct dbfile_config *cfg)
{
	return __dbfile_sync_config(db->db, cfg);
}

static int __dbfile_count_rows(sqlite3_stmt *s, uint64_t *num)
{
	int ret;
	_cleanup_(sqlite3_reset_stmt) sqlite3_stmt *stmt = s;

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_ROW) {
		perror_sqlite(ret, "retrieving count from table (step)");
		return ret;
	}

	*num = sqlite3_column_int64(stmt, 0);
	return 0;
}

int dbfile_get_stats(struct dbhandle *db, struct dbfile_stats *stats)
{
	int ret = 0;
	ret = __dbfile_count_rows(db->stmts.count_b_hashes, &(stats->num_b_hashes));
	if (ret)
		return ret;

	ret = __dbfile_count_rows(db->stmts.count_e_hashes, &(stats->num_e_hashes));
	if (ret)
		return ret;

	ret = __dbfile_count_rows(db->stmts.count_files, &(stats->num_files));
	if (ret)
		return ret;

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

static int get_config_text(sqlite3_stmt *stmt, const char *name, char *val, int len)
{
	int ret;
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
		memcpy(val, local, len);
	}

	if (ret != SQLITE_DONE) {
		perror_sqlite(ret, "retrieving row from config table (step)");
		return ret;
	}

	sqlite3_reset(stmt);

	return 0;
}

static int __dbfile_get_config(sqlite3 *db, struct dbfile_config *cfg)
{
	int ret;
	char uuid[37]; /* 36-bytes uuid + \0 */
	_cleanup_(sqlite3_stmt_cleanup) sqlite3_stmt *stmt = NULL;

#define SELECT_CONFIG "select keyval from config where keyname=?1;"
	ret = sqlite3_prepare_v2(db, SELECT_CONFIG, -1, &stmt, NULL);
	if (ret) {
		perror_sqlite(ret, "preparing statement");
		goto out;
	}

	ret = get_config_int(stmt, "block_size", (int *)&cfg->blocksize);
	if (ret)
		goto out;

	ret = get_config_text(stmt, "hash_type", cfg->hash_type, 8);
	if (ret)
		goto out;

	ret = get_config_int(stmt, "version_major", &cfg->major);
	if (ret)
		goto out;

	ret = get_config_int(stmt, "version_minor", &cfg->minor);
	if (ret)
		goto out;

	ret = get_config_int(stmt, "dedupe_sequence", (int *)&cfg->dedupe_seq);
	if (ret)
		goto out;

	ret = get_config_text(stmt, "fs_uuid", uuid, 36);
	if (ret)
		goto out;

	uuid_parse(uuid, cfg->fs_uuid);

out:
	if (ret != 0)
		perror_sqlite(ret, "__dbfile_get_config");
	return ret;
}

int dbfile_get_config(sqlite3 *db, struct dbfile_config *cfg)
{
	dbfile_config_defaults(cfg);
	return __dbfile_get_config(db, cfg);
}

/* Returns 0 on error, and the inserted rowid on success */
int64_t dbfile_store_file_info(struct dbhandle *db, struct file *dbfile)
{
	int ret;
	_cleanup_(sqlite3_reset_stmt) sqlite3_stmt *stmt = db->stmts.write_file;

	ret = sqlite3_bind_int64(stmt, 1, dbfile->ino);
	if (ret)
		goto bind_error;

	ret = sqlite3_bind_int64(stmt, 2, dbfile->subvol);
	if (ret)
		goto bind_error;

	ret = sqlite3_bind_text(stmt, 3, dbfile->filename, -1, SQLITE_STATIC);
	if (ret)
		goto bind_error;

	ret = sqlite3_bind_int64(stmt, 4, dbfile->size);
	if (ret)
		goto bind_error;

	ret = sqlite3_bind_int64(stmt, 5, dbfile->mtime);
	if (ret)
		goto bind_error;

	ret = sqlite3_bind_int(stmt, 6, dbfile->dedupe_seq);
	if (ret)
		goto bind_error;

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE) {
		perror_sqlite(ret, "executing sql");
		goto out_error;
	}

	return sqlite3_last_insert_rowid(db->db);

bind_error:
	if (ret)
		perror_sqlite(ret, "binding values");
out_error:
	return 0;
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
		perror_sqlite(ret, "removing hashes statement");
		goto out;
	}

	ret = 0;
out:
	return ret;
}

int dbfile_remove_extent_hashes(struct dbhandle *db, uint64_t ino,
					uint64_t subvolid)
{
	_cleanup_(sqlite3_reset_stmt) sqlite3_stmt *stmt = db->stmts.remove_extent_hashes;
	return __dbfile_remove_file_hashes(stmt, ino, subvolid);
}

int dbfile_remove_hashes(struct dbhandle *db, uint64_t ino, uint64_t subvolid)
{
	int ret = 0;
	_cleanup_(sqlite3_reset_stmt) sqlite3_stmt *b_stmt = db->stmts.remove_block_hashes;
	_cleanup_(sqlite3_reset_stmt) sqlite3_stmt *e_stmt = db->stmts.remove_extent_hashes;

	ret += __dbfile_remove_file_hashes(b_stmt, ino, subvolid);
	ret += __dbfile_remove_file_hashes(e_stmt, ino, subvolid);

	return ret;
}

int dbfile_store_block_hashes(struct dbhandle *db, int64_t fileid,
				uint64_t nb_hash, struct block_csum *hashes)
{
	int ret;
	uint64_t i;
	_cleanup_(sqlite3_reset_stmt) sqlite3_stmt *stmt = db->stmts.insert_block;

	for (i = 0; i < nb_hash; i++) {
		ret = sqlite3_bind_int64(stmt, 1, fileid);
		if (ret)
			goto bind_error;

		ret = sqlite3_bind_int64(stmt, 2, hashes[i].loff);
		if (ret)
			goto bind_error;

		ret = sqlite3_bind_blob(stmt, 3, hashes[i].digest, DIGEST_LEN,
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

	return ret;
}

int dbfile_update_scanned_file(struct dbhandle *db, int64_t fileid,
				unsigned char *digest, unsigned int flags)
{
	int ret;
	_cleanup_(sqlite3_reset_stmt) sqlite3_stmt *stmt = db->stmts.update_scanned_file;

	ret = sqlite3_bind_blob(stmt, 1, digest, DIGEST_LEN,
				SQLITE_STATIC);
	if (ret)
		goto bind_error;

	ret = sqlite3_bind_int64(stmt, 2, flags);
	if (ret)
		goto bind_error;

	ret = sqlite3_bind_int64(stmt, 3, fileid);
	if (ret)
		goto bind_error;

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE) {
		perror_sqlite(ret, "executing statement");
		goto out_error;
	}

	ret = 0;
bind_error:
	if (ret)
		perror_sqlite(ret, "binding values");
out_error:
	return ret;
}

int dbfile_store_extent_hashes(struct dbhandle *db, int64_t fileid,
				uint64_t nb_hash, struct extent_csum *hashes)
{
	int ret;
	uint64_t i;
	_cleanup_(sqlite3_reset_stmt) sqlite3_stmt *stmt = db->stmts.insert_extent;

	for (i = 0; i < nb_hash; i++) {
		/*
		 * If len == 0, then this extent was never scanned and
		 * must be skipped.
		 */
		if (hashes[i].len == 0)
			continue;

		ret = sqlite3_bind_int64(stmt, 1, fileid);
		if (ret)
			goto bind_error;

		ret = sqlite3_bind_int64(stmt, 2, hashes[i].loff);
		if (ret)
			goto bind_error;

		ret = sqlite3_bind_int64(stmt, 3, hashes[i].poff);
		if (ret)
			goto bind_error;

		ret = sqlite3_bind_int64(stmt, 4, hashes[i].len);
		if (ret)
			goto bind_error;

		ret = sqlite3_bind_blob(stmt, 5, hashes[i].digest, DIGEST_LEN,
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

	return ret;
}

int dbfile_load_one_filerec(struct dbhandle *db, uint64_t ino, uint64_t subvol,
				   struct filerec **file)
{
	int ret;
	_cleanup_(sqlite3_reset_stmt) sqlite3_stmt *stmt = db->stmts.load_filerec;
	const unsigned char *filename;
	uint64_t size;

	*file = NULL;

	ret = sqlite3_bind_int64(stmt, 1, ino);
	if (ret) {
		perror_sqlite(ret, "binding ino");
		return ret;
	}
	ret = sqlite3_bind_int64(stmt, 2, subvol);
	if (ret) {
		perror_sqlite(ret, "binding subvol");
		return ret;
	}

	ret = sqlite3_step(stmt);
	if (ret == SQLITE_DONE) {
		dprintf("dbfile_load_one_filerec: no file found in hashdb: ino = %lu, subvol = %lu\n", ino, subvol);
		return 0;
	}

	if (ret != SQLITE_ROW) {
		perror_sqlite(ret, "executing statement");
		return ret;
	}

	filename = sqlite3_column_text(stmt, 0);
	size = sqlite3_column_int64(stmt, 1);

	*file = filerec_new((const char *)filename, ino, subvol, size);
	if (!*file)
		return ENOMEM;

	return 0;
}

int dbfile_load_block_hashes(struct dbhandle *db, struct hash_tree *hash_tree,
			     unsigned int seq)
{
	int ret;
	_cleanup_(sqlite3_reset_stmt) sqlite3_stmt *stmt = db->stmts.get_duplicate_blocks;
	uint64_t subvol, ino, loff;
	unsigned char *digest;
	struct filerec *file;

	ret = sqlite3_bind_int64(stmt, 1, seq);
	if (ret) {
		perror_sqlite(ret, "binding value");
		return ret;
	}

	while ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {
		digest = (unsigned char *)sqlite3_column_blob(stmt, 0);
		ino = sqlite3_column_int64(stmt, 1);
		subvol = sqlite3_column_int64(stmt, 2);
		loff = sqlite3_column_int64(stmt, 3);

		file = filerec_find(ino, subvol);
		if (!file) {
			ret = dbfile_load_one_filerec(db, ino, subvol, &file);
			if (ret) {
				fprintf(stderr, "Error loading filerec (%"
					PRIu64",%"PRIu64") from db\n",
					ino, subvol);
				return ret;
			}
		}

		ret = insert_hashed_block(hash_tree, digest, file, loff);
		if (ret)
			return ENOMEM;
	}
	if (ret != SQLITE_DONE) {
		perror_sqlite(ret, "looking up hash");
		return ret;
	}

	sort_file_hash_heads(hash_tree);

	return 0;
}

int dbfile_load_extent_hashes(struct dbhandle *db, struct results_tree *res,
			      unsigned int seq)
{
	int ret;
	_cleanup_(sqlite3_reset_stmt) sqlite3_stmt *stmt = db->stmts.get_duplicate_extents;
	uint64_t subvol, ino, loff, poff, len;
	unsigned char *digest;
	struct filerec *file;

	ret = sqlite3_bind_int64(stmt, 1, seq);
	if (ret) {
		perror_sqlite(ret, "binding value");
		return ret;
	}

	while ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {
		digest = (unsigned char *)sqlite3_column_blob(stmt, 0);
		ino = sqlite3_column_int64(stmt, 1);
		subvol = sqlite3_column_int64(stmt, 2);
		loff = sqlite3_column_int64(stmt, 3);
		len = sqlite3_column_int64(stmt, 4);
		poff = sqlite3_column_int64(stmt, 5);

		file = filerec_find(ino, subvol);
		if (!file) {
			ret = dbfile_load_one_filerec(db, ino, subvol, &file);
			if (ret) {
				fprintf(stderr, "Error loading filerec (%"
					PRIu64",%"PRIu64") from db\n",
					ino, subvol);
				return ret;
			}
		}

		ret = insert_one_result(res, digest, file, loff, len, poff);
		if (ret)
			return ENOMEM;
	}
	if (ret != SQLITE_DONE) {
		perror_sqlite(ret, "looking up hash");
		return ret;
	}

	return 0;
}

int dbfile_load_one_file_extent(struct dbhandle *db, struct filerec *file,
				uint64_t loff, struct file_extent *extent)
{
	int ret;
	_cleanup_(sqlite3_reset_stmt) sqlite3_stmt *stmt = db->stmts.get_file_extent;

	ret = sqlite3_bind_int64(stmt, 1, file->inum);
	if (ret) {
		perror_sqlite(ret, "binding value");
		return ret;
	}

	ret = sqlite3_bind_int64(stmt, 2, file->subvolid);
	if (ret) {
		perror_sqlite(ret, "binding value");
		return ret;
	}

	ret = sqlite3_bind_int64(stmt, 3, loff);
	if (ret) {
		perror_sqlite(ret, "binding value");
		return ret;
	}

	ret = sqlite3_step(stmt);

	/* TODO: drop me when extent_dedupe_worker() is fixed */
	if (ret == SQLITE_DONE)
		return 0;

	if (ret != SQLITE_ROW) {
		perror_sqlite(ret, "retrieving extent info");
		return ret;
	}

	extent->poff = sqlite3_column_int64(stmt, 0);
	extent->loff = sqlite3_column_int64(stmt, 1);
	extent->len = sqlite3_column_int64(stmt, 2);

	return 0;
}

int dbfile_load_nondupe_file_extents(struct dbhandle *db, struct filerec *file,
				     struct file_extent **ret_extents,
				     unsigned int *num_extents)
{
	int ret;
	_cleanup_(sqlite3_reset_stmt) sqlite3_stmt *stmt = db->stmts.get_nondupe_extents;
	uint64_t count = 0, i;
	struct file_extent *extents = NULL;

	ret = sqlite3_bind_int64(stmt, 1, file->inum);
	if (ret) {
		perror_sqlite(ret, "binding values");
		goto out;
	}

	ret = sqlite3_bind_int64(stmt, 2, file->subvolid);
	if (ret) {
		perror_sqlite(ret, "binding values");
		goto out;
	}

	i = 0;
	while ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {
		count++;

		extents = realloc(extents, count * sizeof(struct file_extent));
		if (!extents) {
			ret = ENOMEM;
			goto out;
		}

		extents[i].loff = sqlite3_column_int64(stmt, 0);
		extents[i].len = sqlite3_column_int64(stmt, 1);
		extents[i].poff = sqlite3_column_int64(stmt, 2);

		++i;
	}

	*num_extents = count;
	if (ret != SQLITE_DONE) {
		perror_sqlite(ret, "stepping nondupe extents statement");
		goto out;
	}
	ret = 0;
out:
	*ret_extents = extents;
	if (ret && extents)
		free(extents);
	return ret;
}

static int iter_cb(void *priv, int argc, char **argv,
		char **column [[maybe_unused]])
{
	iter_files_func func = priv;

	abort_on(argc != 3);
	func(argv[0], argv[1], argv[2]);
	return 0;
}

int dbfile_iter_files(struct dbhandle *db, iter_files_func func)
{
	int ret;

#define	LIST_FILES	"select filename, ino, subvol from files;"
	ret = sqlite3_exec(db->db, LIST_FILES, iter_cb, func, NULL);
	if (ret) {
		perror_sqlite(ret, "Running sql to list files.");
		return ret;
	}

	return 0;
}

int dbfile_remove_file(struct dbhandle *db, const char *filename)
{
	int ret;
	_cleanup_(sqlite3_reset_stmt) sqlite3_stmt *stmt = db->stmts.delete_file;

	dprintf("Remove file \"%s\" from the db\n", filename);

	ret = sqlite3_bind_text(stmt, 1, filename, -1, SQLITE_STATIC);
	if (ret) {
		perror_sqlite(ret, "binding filename for sql");
		return ret;
	}

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE) {
		perror_sqlite(ret, "executing sql");
		return ret;
	}

	return 0;
}

void dbfile_list_files(struct dbhandle *db, int (*callback)(void*, int, char**, char**))
{
	int ret;
	char *err;

#define LIST_FILERECS							\
"select ino, subvol, blocks, size, filename from files;"

	ret = sqlite3_exec(db->db, LIST_FILERECS, callback, NULL, &err);
	if (ret) {
		fprintf(stderr, "error %d, executing file search: %s\n", ret,
			err);
		return;
	}
	return;
}

/* Check if the data in the hashfile is in synced with the disk.
 * Returns false only if they match.
 * Returns true if not, or if there is not data found, or on error.
 */
int dbfile_describe_file(struct dbhandle *db, uint64_t inum, uint64_t subvolid,
				struct file *dbfile)
{
	int ret;
	char *buf;
	_cleanup_(sqlite3_reset_stmt) sqlite3_stmt *stmt = db->stmts.select_file_changes;

	/* in-memory databases has no wal support,
	 * so we must do the lock by ourselves
	 */
	if (!options.hashfile)
		dbfile_lock();

	ret = sqlite3_bind_int64(stmt, 1, inum);
	if (ret) {
		perror_sqlite(ret, "binding values");
		goto out;
	}

	ret = sqlite3_bind_int64(stmt, 2, subvolid);
	if (ret) {
		perror_sqlite(ret, "binding values");
		goto out;
	}

	ret = sqlite3_step(stmt);
	if (ret == SQLITE_DONE) {
		ret = 0;
		goto out;
	}

	if (ret != SQLITE_ROW) {
		perror_sqlite(ret, "fetching a file");
		goto out;
	}

	dbfile->mtime = sqlite3_column_int64(stmt, 0);
	dbfile->size = sqlite3_column_int64(stmt, 1);

	buf = (char *)sqlite3_column_text(stmt, 2);
	strncpy(dbfile->filename, buf, PATH_MAX);

	ret = 0;

out:
	if (!options.hashfile)
		dbfile_unlock();
	return ret;
}

int dbfile_load_same_files(struct dbhandle *db, struct results_tree *res,
			   unsigned int seq)
{
	int ret;
	_cleanup_(sqlite3_reset_stmt) sqlite3_stmt *stmt = db->stmts.get_duplicate_files;
	uint64_t subvol, ino, len;
	unsigned char *digest;
	struct filerec *file;

	ret = sqlite3_bind_int64(stmt, 1, seq);
	if (ret) {
		perror_sqlite(ret, "binding value");
		return ret;
	}

	while ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {
		ino = sqlite3_column_int64(stmt, 0);
		subvol = sqlite3_column_int64(stmt, 1);
		len = sqlite3_column_int64(stmt, 2);
		digest = (unsigned char *)sqlite3_column_blob(stmt, 3);

		file = filerec_find(ino, subvol);
		if (!file) {
			ret = dbfile_load_one_filerec(db, ino, subvol, &file);
			if (ret) {
				fprintf(stderr, "Error loading filerec (%"
					PRIu64",%"PRIu64") from db\n",
					ino, subvol);
				return ret;
			}
		}

		ret = insert_one_result(res, digest, file, 0, len, 0);
		if (ret)
			return ENOMEM;
	}
	if (ret != SQLITE_DONE) {
		perror_sqlite(ret, "looking up hash");
		return ret;
	}

	return 0;
}

int dbfile_rename_file(struct dbhandle *db, uint64_t ino, uint64_t subvol,
		       char *path)
{
	int ret;
	_cleanup_(sqlite3_reset_stmt) sqlite3_stmt *stmt = db->stmts.rename_file;

	ret = sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
	if (ret) {
		perror_sqlite(ret, "binding values");
		return ret;
	}

	ret = sqlite3_bind_int64(stmt, 2, ino);
	if (ret) {
		perror_sqlite(ret, "binding values");
		return ret;
	}

	ret = sqlite3_bind_int64(stmt, 3, subvol);
	if (ret) {
		perror_sqlite(ret, "binding values");
		return ret;
	}

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE) {
		perror_sqlite(ret, "renaming a file");
		return ret;
	}

	return 0;
}

void dbfile_set_gdb(struct dbhandle *db)
{
	gdb = db;
}

unsigned int get_max_dedupe_seq(struct dbhandle *db)
{
	_cleanup_(sqlite3_reset_stmt) sqlite3_stmt *stmt = db->stmts.get_max_dedupe_seq;

	int ret = sqlite3_step(stmt);
	if (ret != SQLITE_ROW) {
		fprintf(stderr, "error %d, get max dedupe seq: %s\n",
			ret, sqlite3_errstr(ret));
		return 0;
	}

	return sqlite3_column_int64(stmt, 0);
}

/*
 * Remove entries from the files table that have no extents associated.
 * This can happen if duperemove is ctrl^C while scanning files
 */
int dbfile_prune_unscanned_files(struct dbhandle *db)
{
	int ret;
	_cleanup_(sqlite3_reset_stmt) sqlite3_stmt *stmt = db->stmts.delete_unscanned_files;

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE) {
		perror_sqlite(ret, "executing sql");
		return ret;
	}

	return 0;
}
