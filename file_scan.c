/*
 * file_scan.c
 *
 * Implementation of file scan and checksum phase.
 *
 * Copyright (C) 2014 SUSE.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * Authors: Mark Fasheh <mfasheh@suse.de>
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <limits.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <linux/limits.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <inttypes.h>
#include <linux/magic.h>
#include <sys/statfs.h>
#include <fnmatch.h>
#include <blkid/blkid.h>
#include <libmount/libmount.h>
#include <sys/sysmacros.h>
#include <uuid/uuid.h>

#include <glib.h>

#include "csum.h"
#include "list.h"
#include "filerec.h"
#include "hash-tree.h"
#include "btrfs-util.h"
#include "debug.h"
#include "file_scan.h"
#include "dbfile.h"
#include "util.h"
#include "opt.h"
#include "threads.h"
#include "fiemap.h"

/* This is not in linux/magic.h */
#ifndef	XFS_SB_MAGIC
#define	XFS_SB_MAGIC		0x58465342	/* 'XFSB' */
#endif

static int __scan_file(char *path, struct dbhandle *db, struct statx *st);

bool scan_files_completed = false;
static unsigned long long total_files_count = 0;

static struct threads_pool scan_pool;

#define READ_BUF_LEN (8*1024*1024) // 8MB

LIST_HEAD(exclude_list);

struct buffer {
	char *buf;
	size_t size; /* Size of buf */

	/*
	 * Data has been processed up to this offset
	 * Whatever is afterward should be move at the begining of buf
	 * and not thrown away.
	 */
	size_t dl_offset;

	/* Size of the unprocessed data left in the buf */
	size_t dl_len;

	/* Set to true if the buffer is zeroed */
	bool faked;
};

/*
 * A structure to keep our file hashes before committing them
 * to the hash table
 * extents_count and blocks_count are the size of the allocated arrays
 * extents_index and blocks_index are the index of the next free entries
 */
struct hashes {
	unsigned int extents_count;
	unsigned int extents_index;
	struct extent_csum *extents;

	unsigned int blocks_count;
	unsigned int blocks_index;
	struct block_csum *blocks;
};

struct scan_ctxt {
	int fd;
	size_t filesize;
	size_t off; /* file offset of the last processed bytes */
	struct fiemap *fiemap;
	struct running_checksum *file_csum;
	struct running_checksum *extent_csum;
};

/*
 * Represents the filesystem we are working on
 * Its UUID may be found in the hashfile
 * The dev_t may change at each run, so we discover its
 * value at runtime and use it to quicken the check on non-btrfs fs
 */
struct locked_fs {
	uuid_t uuid;
	dev_t dev;
	bool is_btrfs;
};
struct locked_fs locked_fs = {0,};

static bool allocate_hashes(struct hashes *hashes, struct scan_ctxt *ctxt)
{
	hashes->extents_count = ctxt->fiemap->fm_mapped_extents;
	hashes->extents = calloc(hashes->extents_count, sizeof(struct extent_csum));

	hashes->blocks_count = ctxt->filesize / blocksize + 1;
	hashes->blocks = calloc(hashes->blocks_count, sizeof(struct block_csum));

	return hashes->extents && hashes->blocks;
}

static void free_hashes(struct hashes *hashes)
{
	if (!hashes)
		return;

	if (hashes->extents)
		free(hashes->extents);

	if (hashes->blocks)
		free(hashes->blocks);
}

static int prepare_buffer(struct buffer *buffer)
{
	if (!buffer)
		goto err;

	memset(buffer, 0, sizeof(struct buffer));
	buffer->buf = calloc(1, READ_BUF_LEN);

	if (!(buffer->buf))
		goto err;

	buffer->size = READ_BUF_LEN;

	register_cleanup(&scan_pool, (void*)&free, buffer->buf);
	return 0;

err:
	fprintf(stderr, "prepare_buffer failed\n");
	return 1;
}

static void free_scan_ctxt(struct scan_ctxt *ctxt)
{
	if (!ctxt)
		return;

	if (ctxt->fd >= 0)
		close(ctxt->fd);

	if (ctxt->fiemap)
		free(ctxt->fiemap);

	if (ctxt->file_csum)
		finish_running_checksum(ctxt->file_csum, NULL);

	if (ctxt->extent_csum)
		finish_running_checksum(ctxt->extent_csum, NULL);
}

static void cleanup_dbhandle(void *db)
{
	dbfile_close_handle(db);
}

static struct dbhandle *get_db()
{
	struct dbhandle *db;

	dbfile_lock();
	db = dbfile_open_handle(options.hashfile);
	dbfile_unlock();
	if (db)
		register_cleanup(&scan_pool, (void*)&cleanup_dbhandle, db);
	return db;
}

static int is_excluded(const char *name)
{
	struct exclude_file *exclude, *tmp;

	list_for_each_entry_safe(exclude, tmp, &exclude_list, list) {
		if (fnmatch(exclude->pattern, name, FNM_PATHNAME) == 0) {
			vprintf("Excluding: %s (matches %s)\n", name,
				exclude->pattern);
			return 1;
		}
	}

	return 0;
}

static inline void mnt_unref_table_cleanup(struct libmnt_table **tb)
{
	if (tb && *tb)
		mnt_unref_table(*tb);
}

static inline dev_t stx_to_dev(struct statx *stx)
{
	return makedev(stx->stx_dev_major, stx->stx_dev_minor);
}

/* Get the UUID associated with the FS that stores path */
int get_uuid(char *path, uuid_t *uuid)
{
	struct statx st;
	int ret;
	_cleanup_(mnt_unref_table_cleanup) struct libmnt_table *tb = NULL;
	_cleanup_(closefd) int fd = open(path, O_RDONLY);
	_cleanup_(freep) char *uuid_found = NULL;

	struct libmnt_fs *dev = NULL;

	if (fd == -1) {
		fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno));
		return 1;
	}

	if (is_btrfs(path)) {
		dprintf("get_uuid: %s lives on btrfs\n", path);
		ret = btrfs_get_fsuuid(fd, uuid);
		if (ret) {
			fprintf(stderr, "%s: btrfs_get_fsuuid failed\n",
				path);
			return 1;
		}
	} else {
		dprintf("get_uuid: %s do not live on btrfs\n", path);

		ret = statx(0, path, 0, STATX_BASIC_STATS, &st);
		if (ret) {
			fprintf(stderr, "Failed to stat %s: %s\n",
					path, strerror(errno));
			return 1;
		}

		if (st.stx_dev_major == 0) {
			dprintf("%s lives on an unsupported filesystem, skipping. "
				"Please fill a bug if you think this is a mistake.\n",
					path);
			return 1;
		}

		tb = mnt_new_table_from_file("/proc/self/mountinfo");
		if (!tb) {
			perror("unable to read and parse /proc/self/mountinfo");
			return 1;
		}

		dev = mnt_table_find_devno(tb, stx_to_dev(&st), MNT_ITER_FORWARD);
		if (!dev) {
			fprintf(stderr, "%s: unable to find the mount infos\n",
					path);
			return 1;
		}

		uuid_found = blkid_get_tag_value(NULL, "UUID", mnt_fs_get_source(dev));
		if (!uuid_found) {
			fprintf(stderr, "libblkid could not get uuid for "
					"device %s. Run blkid as root to "
					"populate the cache.\n",
					mnt_fs_get_source(dev));
			return 1;
		}

		uuid_parse(uuid_found, *uuid);
	}
	return 0;
}

static inline uint64_t timestamp_to_nano(struct statx_timestamp t)
{
	return t.tv_sec * 1000000000 + t.tv_nsec;
}

/*
 * Check if path lives on a filesystem that is supported, eg
 * that is known to support deduplication.
 */
bool is_fs_supported(char *path)
{
	struct statfs fs;
	int ret;

	ret = statfs(path, &fs);
	if (ret) {
		fprintf(stderr, "Error %d: %s while check fs type on %s",
			errno, strerror(errno), path);
		return false;
	}

	return (fs.f_type == BTRFS_SUPER_MAGIC ||
		fs.f_type == XFS_SB_MAGIC);
}

/* Check if path should be processed:
 * - is path not excluded ?
 * - is path a file or directory ?
 * - is path not an empty file ?
 * - does path lives on our locked filesystem ?
 *   for files, we only do that check if the parent is not checked
 *
 * Returns true is the file is legit, false if not (or on error)
 */
bool check_file(struct dbhandle *db, char *path, struct statx *st, bool parent_checked)
{
	int ret;
	struct dbfile_config cfg;
	uuid_t uuid = {0,};

	if (is_excluded(path))
		return false;

	if (!S_ISREG(st->stx_mode) && !S_ISDIR(st->stx_mode)) {
		vprintf("Skipping non-regular/non-directory file %s\n", path);
		return false;
	}

	if (S_ISREG(st->stx_mode) && st->stx_size == 0) {
		vprintf("Skipping empty file %s\n", path);
		return false;
	}

	/* There is no need to check if the file lives in our locked fs.
	 * It is a regular file and we already check its parent.
	 */
	if (S_ISREG(st->stx_mode) && parent_checked)
		return true;

	/* Locked-fs checks */
	/* First, try to get uuid from the hashfile */
	if (uuid_is_null(locked_fs.uuid)) {
		dprintf("Looking our fs uuid from the hashfile\n");
		ret = dbfile_get_config(db->db, &cfg);
		if (ret)
			return 1;

		if (!uuid_is_null(cfg.fs_uuid))
			uuid_copy(locked_fs.uuid, cfg.fs_uuid);
	}

	/* hashfile was empty. We lock on the file. */
	if (uuid_is_null(locked_fs.uuid)) {
		dprintf("Empty hashfile, locking on the current file\n");
		ret = get_uuid(path, &locked_fs.uuid);
		if (ret)
			return false;

		locked_fs.dev = stx_to_dev(st);
		locked_fs.is_btrfs = is_btrfs(path);

		if (!is_fs_supported(path))
			fprintf(stderr, "Warn: filesystem for %s is not known to "
				"support deduplication.\n", path);

		return true;
	}

	/* Hashfile was not empty */
	/* We miss runtime data, check if our fille is in the valid fs
	 * and store them for future calls
	 */
	if (locked_fs.dev == 0) {
		ret = get_uuid(path, &uuid);
		if (ret)
			return false;

		if (uuid_compare(uuid, locked_fs.uuid) != 0) {
			fprintf(stderr, "%s lives on fs ", path);
			debug_print_uuid(stderr, uuid);
			fprintf(stderr, " will we are locked on fs ");
			debug_print_uuid(stderr, locked_fs.uuid);
			fprintf(stderr, ".\n");
			return false;
		}

		locked_fs.dev = stx_to_dev(st);
		locked_fs.is_btrfs = is_btrfs(path);
		return true;
	}

	if (!locked_fs.is_btrfs)
		return locked_fs.dev == stx_to_dev(st);

	/* On btrfs, we must always fetch the UUID */
	ret = get_uuid(path, &uuid);
	if (ret)
		return false;

	return uuid_compare(uuid, locked_fs.uuid) == 0;
}

void fs_get_locked_uuid(uuid_t *uuid)
{
	if (uuid)
		uuid_copy(*uuid, locked_fs.uuid);
}

static int get_dirent_type(struct dirent *entry, int fd, const char *path)
{
	int ret;
	struct statx st;

	if (entry->d_type != DT_UNKNOWN)
		return entry->d_type;

	/*
	 * FS doesn't support file type in dirent, do this the old
	 * fashioned way. We translate mode to DT_* for the
	 * convenience of the caller.
	 */
	ret = statx(fd, entry->d_name, AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS, &st);
	if (ret || !(st.stx_mask & STATX_BASIC_STATS)) {
		fprintf(stderr,
			"Error %d: %s while getting type of file %s/%s. "
			"Skipping.\n",
			errno, strerror(errno), path, entry->d_name);
		return DT_UNKNOWN;
	}

	if (S_ISREG(st.stx_mode))
		return DT_REG;
	if (S_ISDIR(st.stx_mode))
		return DT_DIR;
	if (S_ISBLK(st.stx_mode))
		return DT_BLK;
	if (S_ISCHR(st.stx_mode))
		return DT_CHR;
	if (S_ISFIFO(st.stx_mode))
		return DT_FIFO;
	if (S_ISLNK(st.stx_mode))
		return DT_LNK;
	if (S_ISSOCK(st.stx_mode))
		return DT_SOCK;

	return DT_UNKNOWN;
}

/*
 * Returns nonzero on fatal errors only
 */
static int walk_dir(char *path, struct dbhandle *db)
{
	int ret = 0;
	struct dirent *entry;
	struct statx st;
	_cleanup_(closedirectory) DIR *dirp = opendir(path);

	/* Overallocate to peace the compiler. An abort will check the actual values. */
	char child[PATH_MAX + 257] = { 0, };

	if (dirp == NULL) {
		fprintf(stderr, "Error %d: %s while opening directory %s\n",
			errno, strerror(errno), path);
		return 0;
	}

	while(true) {
		errno = 0;
		entry = readdir(dirp);
		if (!entry && errno == 0) /* End of directory */
			break;

		if (errno != 0) {
			fprintf(stderr, "Error %d: %s while reading directory %s\n",
				errno, strerror(errno), path);
			return 0;
		}

		if (strcmp(entry->d_name, ".") == 0
		    || strcmp(entry->d_name, "..") == 0)
			continue;

		entry->d_type = get_dirent_type(entry, dirfd(dirp), path);

		if (entry->d_type != DT_REG &&
		    !(options.recurse_dirs && entry->d_type == DT_DIR))
			continue;

		/* This should never happen */
		abort_on(strlen(path) + strlen(entry->d_name) > PATH_MAX);

		if (strcmp(path, "/") == 0)
			sprintf(child, "/%s", entry->d_name);
		else
			sprintf(child, "%s/%s", path, entry->d_name);

		ret = statx(0, child, 0, STATX_BASIC_STATS, &st);
		if (ret || !(st.stx_mask | STATX_BASIC_STATS)) {
			fprintf(stderr, "Failed to stat %s: %s\n",
					path, strerror(errno));
			continue;
		}

		if (!check_file(db, child, &st, true))
			continue;

		if (entry->d_type == DT_REG)
			ret = __scan_file(child, db, &st);
		else
			ret = walk_dir(child, db);
		if (ret)
			return ret;
	}

	return 0;
}

static inline bool is_file_renamed(char *path_in_db, char *path)
{
	struct stat st;

	if (strlen(path_in_db) == 0)
		return true;

	if (strcmp(path_in_db, path) == 0)
		return false;

	/*
	 * Old path and new paths differs. Could be hardlink,
	 * so we check if the old still exists.
	 */
	return true ? lstat(path_in_db, &st) : false;
}

/*
 * Returns nonzero on fatal errors only
 * This function schedules csum_whole_file()
 * The caller must call check_file() before and must not call
 * this if path is not a regular file.
 */
static int __scan_file(char *path, struct dbhandle *db, struct statx *st)
{
	int ret;
	struct file dbfile = {0,};
	static unsigned int seq = 0, counter = 0;
	GError *err = NULL;
	struct file_to_scan *file;
	int64_t fileid = 0;
	bool file_renamed;

	/*
	 * The first call initializes the static variable
	 * from the global dedupe_seq
	 * The subsequents calls will increase it every <batchsize> times
	 */
	if (seq == 0)
		seq = dedupe_seq + 1;

	abort_on(!S_ISREG(st->stx_mode));

	if (locked_fs.is_btrfs) {
		_cleanup_(closefd) int fd;
		fd = open(path, O_RDONLY);
		if (fd == -1) {
			fprintf(stderr, "Error %d: %s while opening file \"%s\". "
				"Skipping.\n", errno, strerror(errno), path);
			return 0;
		}

		/*
		 * Inodes between subvolumes on a btrfs file system
		 * can have the same i_ino. Get the subvolume id of
		 * our file so hard link detection works.
		 */
		ret = lookup_btrfs_subvol(fd, &(dbfile.subvol));
		if (ret) {
			fprintf(stderr,
				"Error %d: %s while finding subvol for file "
				"\"%s\". Skipping.\n", ret, strerror(ret),
				path);
			return 0;
		}
	}

	/*
	 * Check the database to see if that file need rescan or not.
	 */
	ret = dbfile_describe_file(db, st->stx_ino, dbfile.subvol, &dbfile);
	if (ret) {
		vprintf("dbfile_describe_file failed\n");
		return 0;
	}

	file_renamed = is_file_renamed(dbfile.filename, path);

	/* Database is up-to-date, nothing more to do */
	if (dbfile.mtime == timestamp_to_nano(st->stx_mtime)
	    && dbfile.size == st->stx_size && !file_renamed)
		return 0;

	if (options.batch_size != 0) {
		counter += 1;
		if (counter >= options.batch_size) {
			seq++;
			counter = 0;
		}
	}

	dbfile.ino = st->stx_ino;
	dbfile.size = st->stx_size;
	strncpy(dbfile.filename, path, PATH_MAX);
	dbfile.mtime = timestamp_to_nano(st->stx_mtime);
	dbfile.dedupe_seq = seq;

	dbfile_lock();
	dbfile_begin_trans(db->db);

	if (file_renamed) {
		ret = dbfile_rename_file(db, dbfile.id, path);
		if (ret) {
			vprintf("dbfile_rename_file failed\n");
			return 0;
		}
	}

	if (dbfile.mtime != 0 || dbfile.size != 0) {
		/*
		 * The file was scanned in a previous run.
		 * We will rescan it, so let's remove old hashes
		 */
		dbfile_remove_hashes(db, dbfile.id);
	}

	/* Upsert the file record */
	fileid = dbfile_store_file_info(db, &dbfile);
	if (!fileid) {
		dbfile_abort_trans(db->db);
		dbfile_unlock();
		return 0;
	}

	dbfile_commit_trans(db->db);
	dbfile_unlock();

	/* Schedule the file for scan */
	file = malloc(sizeof(struct file_to_scan)); /* Freed by csum_whole_file() */

	file->path = strdup(path);
	file->fileid = fileid;
	file->filesize = st->stx_size;

	total_files_count++;
	file->file_position = total_files_count;

	if(!g_thread_pool_push(scan_pool.pool, file, &err)) {
		fprintf(stderr, "g_thread_pool_push: %s\n", err->message);
		g_error_free(err);
		err = NULL;
		free(file);
		return 1;
	}

	return 0;
}

/* The entry point for files passed by the user */
int scan_file(char *in_path, struct dbhandle *db)
{
	struct statx st;
	char path[PATH_MAX];
	int ret;

	/*
	 * Sanitize the file name and get absolute path. This avoids:
	 *
	 * - needless filerec writes to the db when we have
	 *   effectively the same filename but the components have extra '/'
	 *
	 * - Absolute path allows the user to re-run this hash from
	 *   any directory.
	 */
	if (realpath(in_path, path) == NULL) {
		fprintf(stderr, "Error %d: %s while getting path to file %s. "
			"Skipping.\n",
			errno, strerror(errno), in_path);
		return 0;
	}

	ret = statx(0, path, 0, STATX_BASIC_STATS, &st);
	if (ret || !(st.stx_mask & STATX_BASIC_STATS)) {
		fprintf(stderr, "Error %d: %s while stating file %s. "
			"Skipping.\n",
			errno, strerror(errno), path);
		return 0;
	}

	if (!check_file(db, path, &st, false))
		return 0;

	if (S_ISREG(st.stx_mode))
		return __scan_file(path, db, &st);
	else
		return walk_dir(path, db);
}

/* Check if the block starting at buf is full of zeroes */
static inline int is_block_zeroed(void *buf)
{
	return buf && ((int*)buf)[0] == 0 && !memcmp(buf, buf + 1, blocksize - 1);
}

static int add_block_hash(struct hashes *hashes,
			  uint64_t loff, unsigned char *digest)
{
	struct block_csum *retp;

	if (hashes->blocks_index + 1 > hashes->blocks_count) {
		/* Somehow, we did not allocate enough memory */
		hashes->blocks_count++;
		retp = realloc(hashes->blocks, sizeof(struct block_csum) * hashes->blocks_count);
		if (!retp)
			return -ENOMEM;
		hashes->blocks = retp;
	}

	hashes->blocks[hashes->blocks_index].loff = loff;
	memcpy(hashes->blocks[hashes->blocks_index].digest, digest, DIGEST_LEN);
	hashes->blocks_index++;
	return 0;
}

static void print_progress(unsigned long long pos, char* path)
{
	unsigned int leading_space = num_digits(total_files_count);

	/*
	 * We do not print the percentage unless all files are actually
	 * pushed into the thread queue
	 */
	if (scan_files_completed) {
		qprintf("[%0*llu/%llu] (%05.2f%%) csum: %s\n",
			leading_space, pos, total_files_count,
			(double)pos / (double)total_files_count * 100,
			path);
	} else {
		qprintf("[%0*llu/%llu] csum: %s\n",
			leading_space, pos, total_files_count,
			path);
	}
}

/*
 * Check if the area should be scanned.
 */
static bool is_area_ignored(struct fiemap *fiemap, size_t start, size_t len)
{
	size_t end = start + len;
	struct fiemap_extent *current_extent;
	while (start < end) {
		current_extent = get_extent(fiemap, start, NULL);

		/* File changed since we fiemap */
		if (!current_extent)
			return false;

		if (current_extent->fe_flags & FIEMAP_SKIP_FLAGS)
			return true;

		if (current_extent->fe_flags & FIEMAP_EXTENT_LAST)
			break;
		start = current_extent->fe_logical + current_extent->fe_length + 1;
	}
	return false;
}

/*
 * Check if the block starting at off should be ignored.
 */
static inline bool is_block_ignored(struct fiemap *fiemap, size_t off)
{
	return is_area_ignored(fiemap, off, blocksize);
}

static int process_block(char *buf, unsigned int bsize,
		size_t file_off, struct hashes *hashes)
{
	unsigned char digest[DIGEST_LEN];
	checksum_block(buf, bsize, digest);
	return add_block_hash(hashes, file_off, digest);
}

/*
 * Processes entire blocks from buffer.
 * Partial blocks are ignored: the buffer needs to be refilled.
 * Returns the total of bytes processed.
*/
static ssize_t process_blocks(struct scan_ctxt *ctxt, struct buffer *buffer,
			      struct hashes *hashes)
{
	int ret = 0;
	unsigned int nb_blocks = buffer->dl_len / blocksize;
	size_t curr_file_off = ctxt->off;

	/* We do not actually need to process the blocks */
	if (!options.do_block_hash || buffer->faked)
		return buffer->dl_len;

	for (unsigned int i = 0; i < nb_blocks; i++) {
		if (!is_block_ignored(ctxt->fiemap, curr_file_off) &&
		    !(options.skip_zeroes &&
		      is_block_zeroed(buffer->buf + buffer->dl_offset))) {
			ret = process_block(buffer->buf + i * blocksize,
					    blocksize, curr_file_off, hashes);
			if (ret)
				return ret;
		}

		curr_file_off += blocksize;
	}

	return nb_blocks * blocksize;
}

static int store_extent(struct scan_ctxt *ctxt, struct hashes *hashes, struct fiemap_extent *extent)
{
	struct extent_csum *retp;

	if (hashes->extents_index + 1 > hashes->extents_count) {
		/* Somehow, we did not allocate enough memory */
		hashes->extents_count++;
		retp = realloc(hashes->extents, sizeof(struct extent_csum) * hashes->extents_count);
		if (!retp)
			return -ENOMEM;
		hashes->extents = retp;
	}

	if (extent->fe_flags & FIEMAP_SKIP_FLAGS) {
		hashes->extents[hashes->extents_index].len = 0;
	} else {
		hashes->extents[hashes->extents_index].loff = extent->fe_logical;
		hashes->extents[hashes->extents_index].poff = extent->fe_physical;
		hashes->extents[hashes->extents_index].len  = extent->fe_length;
		finish_running_checksum(ctxt->extent_csum, hashes->extents[hashes->extents_index].digest);
		ctxt->extent_csum = NULL;
	}
	hashes->extents_index++;

	return 0;
}

static int process_extents(struct scan_ctxt *ctxt, struct buffer *buffer,
			   struct hashes *hashes, size_t bytes)
{
	/* Local variables to not overwrite the context etc */
	size_t file_off = ctxt->off;
	size_t buf_off = 0;

	int ret;
	struct fiemap_extent *extent;
	size_t ext_end_off;
	size_t to_add;

	while (file_off < ctxt->off + bytes) {
		extent = get_extent(ctxt->fiemap, file_off, NULL);
		if (!extent) {
			fprintf(stderr, "process_extents: unable to get extent\n");

			/* Cleanup the partial checksum and skip
			 * the rest of the buffer
			 */
			if (ctxt->extent_csum)
				finish_running_checksum(ctxt->extent_csum, NULL);
			ctxt->extent_csum = NULL;
			return 1;
		}

		ext_end_off = extent->fe_logical + extent->fe_length;

		if (ext_end_off > ctxt->off + bytes)
			/* Extent ends after our buffer */
			to_add = bytes - buf_off;
		else
			to_add = ext_end_off - file_off;

		if (!(extent->fe_flags & FIEMAP_SKIP_FLAGS)) {
			if (ctxt->extent_csum == NULL) {
				ctxt->extent_csum = start_running_checksum();
			}

			add_to_running_checksum(ctxt->extent_csum, (unsigned char*)buffer->buf + buf_off, to_add);
		}

		assert(file_off + to_add <= ctxt->off + bytes);

		buf_off += to_add;
		file_off += to_add;

		/*
		 * ext_end_off may be 4k-aligned:
		 * Unless FIEMAP_EXTENT_NOT_ALIGNED is returned,
		 * fe_logical, fe_physical, and fe_length will be aligned
		 * to the block size of the file system.
		 * So, if we are processing the last extent, then
		 * ext_end_off may be larger than the filesize. For those extents, add
		 * the part that will never exist.
		 */
		size_t dummy = 0;
		if (extent->fe_flags & FIEMAP_EXTENT_LAST)
			dummy = ext_end_off - ctxt->filesize;
		if (file_off + dummy == ext_end_off) {
			ret = store_extent(ctxt, hashes, extent);
			if (ret)
				return ret;
		}
	}
	return 0;
}

/*
 * Try to fill the buffer with more data from the file
 * Unprocessed data could live in the buffer: in this case,
 * we avoid re-reading that data and, instead, move it at the beginning
 * of the buffer and (try to) fill whatever space is left.
 * Returns 1 on success, 0 when EOF is reached, negative int on error.
 */
static int fill_buffer(struct scan_ctxt *ctxt, struct buffer *buffer)
{
	ssize_t ret;

	/*
	 * The entire buffer could be ignored. Let's fast forward
	 * and mark the buffer as faked
	 */
	if (is_area_ignored(ctxt->fiemap, ctxt->off, buffer->size)
			&& ctxt->off + buffer->size <= ctxt->filesize) {
		memset(buffer->buf, 0, buffer->size);
		buffer->dl_len = buffer->size;
		buffer->dl_offset = 0;
		buffer->faked = true;

		if (ctxt->filesize <= ctxt->off + buffer->size)
			return 0; /* Simulate EOF */
		return 1;
	}

	/* Move leftovers back at the begining of the buffer */
	if (buffer->dl_len != 0)
		memmove(buffer->buf, buffer->buf + buffer->dl_offset, buffer->dl_len);
	buffer->dl_offset = 0;

	buffer->faked = false;

	ret = pread(ctxt->fd, buffer->buf + buffer->dl_len,
		buffer->size - buffer->dl_len, ctxt->off + buffer->dl_len);
	if (ret > 0)
		buffer->dl_len += ret;

	/* We must never overflow */
	assert(buffer->dl_offset + buffer->dl_len <= buffer->size);

	if (ret < 0)
		return ret;

	if (ret == 0 || ctxt->off + buffer->dl_len == ctxt->filesize) /* EOF */
		return 0;
	return buffer->dl_len;
}

static inline bool is_inlined(struct scan_ctxt *ctxt)
{
	struct fiemap_extent *extent;

	extent = get_extent(ctxt->fiemap, ctxt->filesize - 1, NULL);
	return extent && extent->fe_flags & FIEMAP_EXTENT_DATA_INLINE;
}

static void csum_whole_file(struct file_to_scan *file)
{
	int ret = 0;

	_cleanup_(free_hashes) struct hashes hashes = {0,};
	_cleanup_(free_scan_ctxt) struct scan_ctxt ctxt = {0,};
	unsigned char file_digest[DIGEST_LEN];

	/* Those variables will be initialized only once
	 * during the thread lifetime
	 */
	static struct dbhandle *db = NULL;
	static __thread struct buffer buffer = {0,};

	/* Dummy variables used to trigger the cleanup code */
	_cleanup_(freep) char *path = file->path;
	_cleanup_(freep) struct file_to_scan *clean_file = file;

	/* Used to detected eof if file changed since
	 * we stat() it
	 */
	bool eof_reached = false;

	print_progress(file->file_position, file->path);

	if (!(buffer.buf)) {
		ret = prepare_buffer(&buffer);
		if (ret) {
			fprintf(stderr, "unable to prepare our read buffer\n");
			return;
		}
	} else {
		/* Clean leftovers from another call */
		buffer.dl_offset = 0;
		buffer.dl_len = 0;
	}

	if (!db)
		db = get_db();
	if (!db) {
		fprintf(stderr, "csum_whole_file: unable to connect to the database\n");
		return;
	}

	ctxt.filesize = file->filesize;
	ctxt.file_csum = start_running_checksum();
	if (!ctxt.file_csum)
		return;

	ctxt.fd = open(file->path, O_RDONLY);
	if (ctxt.fd == -1) {
		fprintf(stderr, "csum_whole_file: Error %d: %s while opening file \"%s\". "
			"Skipping.\n", errno, strerror(errno), file->path);
		return;
	}

	ctxt.fiemap = do_fiemap(ctxt.fd);
	if (!ctxt.fiemap)
		return;

	if (!allocate_hashes(&hashes, &ctxt)) {
		fprintf(stderr, "allocate_hashes failed\n");
		return;
	}

	/*
	 * Main loop:
	 * - grab some data into the buffer
	 * - try to process as must entire blocks as possible
	 * - consume that amount of bytes for the file csum
	 * - consume that amount of bytes for the extents
	 * loop again until pread returns 0 or
	 * until we reach the expected EOF, based on the expected filesize
	 */
	while (ctxt.off < ctxt.filesize) {
		/* In the buffer, how much bytes are processed as blocks
		 * Extents processing and file processing will not consumme
		 * more than that amount of bytes
		 */
		ssize_t bytes_processed = 0;

		ret = fill_buffer(&ctxt, &buffer);
		if (ret < 0) {
			ret = errno;
			fprintf(stderr, "Unable to read file %s: %s\n",
				file->path, strerror(ret));
			return;
		}

		if (ret == 0)
			eof_reached = true;

		bytes_processed = process_blocks(&ctxt, &buffer, &hashes);
		if (bytes_processed < 0) {
			fprintf(stderr, "process_blocks failed somehow\n");
			return;
		}

		/* Process the last partial block */
		if (eof_reached && (size_t)bytes_processed < buffer.dl_len) {
			ret = process_block(buffer.buf + bytes_processed,
					    buffer.dl_len - bytes_processed,
					    ctxt.off + bytes_processed,
					    &hashes);
			if (ret) {
				fprintf(stderr, "Unable to process %s's last block\n", file->path);
				return;
			}

			bytes_processed += buffer.dl_len - bytes_processed;
		}

		add_to_running_checksum(ctxt.file_csum, (unsigned char*)(buffer.buf), bytes_processed);

		if (!options.only_whole_files) {
			ret = process_extents(&ctxt, &buffer, &hashes, bytes_processed);
			if (ret)
				break;
		}

		buffer.dl_offset = bytes_processed;
		buffer.dl_len -= bytes_processed;

		/* Ack the processed data and move the current offset accordingly */
		ctxt.off += bytes_processed;

		if (eof_reached)
			/* File may have change */
			break;
	}

	if (ctxt.off != ctxt.filesize) {
		fprintf(stderr, "file %s changed\n", file->path);
		return;
	}

	finish_running_checksum(ctxt.file_csum, file_digest);
	ctxt.file_csum = NULL;

	dbfile_lock();
	ret = dbfile_begin_trans(db->db);
	if (ret) {
		dbfile_unlock();
		return;
	}

	/* Do not store the blocks if the file is inlined */
	if (hashes.blocks_index != 0 && !is_inlined(&ctxt)) {
		ret = dbfile_store_block_hashes(db, file->fileid,
						hashes.blocks_index, hashes.blocks);
		if (ret) {
			dbfile_abort_trans(db->db);
			dbfile_unlock();
			return;
		}
	}


	if (hashes.extents_index != 0) {
		ret = dbfile_store_extent_hashes(db, file->fileid, hashes.extents_index, hashes.extents);
		if (ret) {
			dbfile_abort_trans(db->db);
			dbfile_unlock();
			return;
		}
	}

	/* Flag the file if its last extent is INLINED.
	 * Attempt to deduplicate those will never succeed and will produce a lot
	 * of needless work: https://github.com/markfasheh/duperemove/issues/316
	 */
	ret = dbfile_update_scanned_file(db, file->fileid, file_digest,
			is_inlined(&ctxt) ? FILE_INLINED : 0);
	if (ret) {
		dbfile_abort_trans(db->db);
		dbfile_unlock();
		return;
	}

	ret = dbfile_commit_trans(db->db);
	if (ret) {
		dbfile_unlock();
		return;
	}

	dbfile_unlock();
}

int add_exclude_pattern(const char *pattern)
{
	char cwd[PATH_MAX] = { 0, };

	/* Overallocate to peace the compiler. */
	char exp_pattern[PATH_MAX * 2 + 1] = { 0, };
	struct exclude_file *exclude = malloc(sizeof(*exclude));

	if (!exclude)
		return 1;

	if (pattern[0] == '/') {
		exclude->pattern = strdup(pattern);
	} else {
		getcwd(cwd, PATH_MAX);

		if (strlen(cwd) + strlen(pattern) > PATH_MAX) {
			fprintf(stderr, "Error: cannot prepend cwd to %s\n", pattern);
			return 1;
		}

		sprintf(exp_pattern, "%s/%s", cwd, pattern);
		exclude->pattern = strdup(exp_pattern);
	}

	printf("Adding exclude pattern: %s\n", exclude->pattern);

	list_add_tail(&exclude->list, &exclude_list);
	return 0;
}

void filescan_prepare_pool()
{
	abort_on(scan_pool.pool);
	setup_pool(&scan_pool, csum_whole_file, NULL);
	abort_on(!scan_pool.pool);
}

void filescan_free_pool()
{
	free_pool(&scan_pool);
}

void add_file_fdupes(char *path)
{
	struct statx st;
	int ret;

	ret = statx(0, path, 0, STATX_BASIC_STATS, &st);
	if (ret || !(st.stx_mask & STATX_BASIC_STATS)) {
		fprintf(stderr, "statx on %s: %s\n", path, strerror(errno));
		return;
	}
	filerec_new(path, st.stx_ino, st.stx_size);
}
