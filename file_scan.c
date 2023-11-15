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

static dev_t one_fs_dev;
static uint64_t one_fs_btrfs;

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

static struct dbhandle *get_db()
{
	struct dbhandle *db;

	dbfile_lock();
	db = dbfile_open_handle(options.hashfile);
	dbfile_unlock();
	if (db)
		register_cleanup(&scan_pool, (void*)&dbfile_close_handle, db);
	return db;
}

dev_t fs_onefs_dev(void)
{
	return one_fs_dev;
}

uint64_t fs_onefs_id(void)
{
	return one_fs_btrfs;
}

static int get_dirent_type(struct dirent *entry, int fd, const char *path)
{
	int ret;
	struct stat st;

	if (entry->d_type != DT_UNKNOWN)
		return entry->d_type;

	/*
	 * FS doesn't support file type in dirent, do this the old
	 * fashioned way. We translate mode to DT_* for the
	 * convenience of the caller.
	 */
	ret = fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW);
	if (ret) {
		fprintf(stderr,
			"Error %d: %s while getting type of file %s/%s. "
			"Skipping.\n",
			errno, strerror(errno), path, entry->d_name);
		return DT_UNKNOWN;
	}

	if (S_ISREG(st.st_mode))
		return DT_REG;
	if (S_ISDIR(st.st_mode))
		return DT_DIR;
	if (S_ISBLK(st.st_mode))
		return DT_BLK;
	if (S_ISCHR(st.st_mode))
		return DT_CHR;
	if (S_ISFIFO(st.st_mode))
		return DT_FIFO;
	if (S_ISLNK(st.st_mode))
		return DT_LNK;
	if (S_ISSOCK(st.st_mode))
		return DT_SOCK;

	return DT_UNKNOWN;
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

static int walk_dir(char *path, struct dbhandle *db)
{
	int ret = 0;
	struct dirent *entry;
	_cleanup_(closedirectory) DIR *dirp = opendir(path);

	/* Overallocate to peace the compiler. An abort will check the actual values. */
	char child[PATH_MAX + 256] = { 0, };

	if (dirp == NULL) {
		fprintf(stderr, "Error %d: %s while opening directory %s\n",
			errno, strerror(errno), path);
		return 0;
	}

	while(true) {
		errno = 0;
		entry = readdir(dirp);
		if (!entry) /* End of directory or error */
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

		if (entry->d_type == DT_REG ||
		    (options.recurse_dirs && entry->d_type == DT_DIR)) {

			/* This should never happen */
			abort_on(strlen(path) + strlen(entry->d_name) > PATH_MAX);

			sprintf(child, "%s/%s", path, entry->d_name);
			ret = scan_file(child, db);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static bool will_cross_mountpoint(dev_t dev, uint64_t btrfs_fsid)
{
	abort_on(one_fs_dev && one_fs_btrfs);

	if (!one_fs_dev && !one_fs_btrfs) {
		if (btrfs_fsid)
			one_fs_btrfs = btrfs_fsid;
		else
			one_fs_dev = dev;
	}

	if ((one_fs_dev && (one_fs_dev != dev)) ||
	    (one_fs_btrfs && (btrfs_fsid != one_fs_btrfs)))
		return true;

	return false;
}

/*
 * Returns nonzero on fatal errors only
 */
int scan_file(const char *path, struct dbhandle *db)
{
	int ret;
	struct stat st;
	char abspath[PATH_MAX];
	uint64_t mtime = 0, size = 0;
	static unsigned int seq = 0, counter = 0;
	GError *err = NULL;
	struct file_to_scan *file;
	int64_t fileid = 0;

	/*
	 * The first call initializes the static variable
	 * from the global dedupe_seq
	 * The subsequents calls will increase it every <batchsize> times
	 */
	if (seq == 0)
		seq = dedupe_seq + 1;

	_cleanup_(closefd) int fd = -1;
	uint64_t subvolid;
	struct statfs fs;

	/*
	 * Sanitize the file name and get absolute path. This avoids:
	 *
	 * - needless filerec writes to the db when we have
	 *   effectively the same filename but the components have extra '/'
	 *
	 * - Absolute path allows the user to re-run this hash from
	 *   any directory.
	 */
	if (realpath(path, abspath) == NULL) {
		fprintf(stderr, "Error %d: %s while getting path to file %s. "
			"Skipping.\n",
			errno, strerror(errno), path);
		return 0;
	}

	if (is_excluded(abspath))
		return 0;

	ret = lstat(abspath, &st);
	if (ret) {
		fprintf(stderr, "Error %d: %s while stating file %s. "
			"Skipping.\n",
			errno, strerror(errno), abspath);
		return 0;
	}

	if (st.st_size == 0) {
		vprintf("Skipping empty file %s\n", abspath);
		return 0;
	}

	if (S_ISDIR(st.st_mode)) {
		uint64_t btrfs_fsid;
		dev_t dev = st.st_dev;

		/*
		 * Device doesn't work for btrfs as it changes between
		 * subvolumes. We know how to get a unique fsid though
		 * so use that in the case where we are on btrfs.
		 */
		ret = check_btrfs_get_fsid(abspath, &btrfs_fsid);
		if (ret) {
			vprintf("Skipping directory %s due to error %d: %s\n",
				abspath, ret, strerror(ret));
			return 0;
		}

		/* Don't cross mount points since dedup doesn't work across */
		if (will_cross_mountpoint(dev, btrfs_fsid)) {
			vprintf("Mountpoint traversal disallowed: %s \n",
				abspath);
			return 0;
		}

		if (walk_dir(abspath, db))
			return 1;
		return 0;
	}

	if (!S_ISREG(st.st_mode)) {
		vprintf("Skipping non-regular file %s\n", abspath);
		return 0;
	}

	fd = open(abspath, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Error %d: %s while opening file \"%s\". "
			"Skipping.\n", ret, strerror(ret), abspath);
		return 0;
	}

	ret = fstatfs(fd, &fs);
	if (ret) {
		fprintf(stderr, "Error %d: %s while doing fs stat on \"%s\". "
			"Skipping.\n", ret, strerror(ret), abspath);
		return 0;
	}

	if (options.run_dedupe == 1 &&
	    ((fs.f_type != BTRFS_SUPER_MAGIC &&
	      fs.f_type != XFS_SB_MAGIC))) {
		fprintf(stderr,	"\"%s\": Can only dedupe files on btrfs or xfs, "
			"use -d -d to override\n", abspath);
		return ENOSYS;
	}

	if (fs.f_type == BTRFS_SUPER_MAGIC) {
		/*
		 * Inodes between subvolumes on a btrfs file system
		 * can have the same i_ino. Get the subvolume id of
		 * our file so hard link detection works.
		 */
		ret = lookup_btrfs_subvolid(fd, &subvolid);
		if (ret) {
			fprintf(stderr,
				"Error %d: %s while finding subvolid for file "
				"\"%s\". Skipping.\n", ret, strerror(ret),
				abspath);
			return 0;
		}
	} else {
		subvolid = st.st_dev;
	}

	/*
	 * Check the database to see if that file need rescan or not.
	 */
	ret = dbfile_describe_file(db, st.st_ino, subvolid, &mtime, &size);
	if (ret) {
		vprintf("dbfile_describe_file failed\n");
		return 0;
	}

	/* Database is up-to-date, nothing more to do */
	if (mtime == timespec_to_nano(&(st.st_mtim)) && size == (uint64_t)st.st_size)
		return 0;

	if (options.batch_size != 0) {
		counter += 1;
		if (counter >= options.batch_size) {
			seq++;
			counter = 0;
		}
	}

	dbfile_lock();
	dbfile_begin_trans(db->db);
	if (mtime != 0 || size != 0) {
		/*
		 * The file was scanned in a previous run.
		 * We will rescan it, so let's remove old hashes
		 */
		dbfile_remove_hashes(db, st.st_ino, subvolid);
	}

	/* Upsert the file record */
	fileid = dbfile_store_file_info(db, st.st_ino, subvolid, abspath, st.st_size, timespec_to_nano(&(st.st_mtim)), seq);
	if (!fileid) {
		dbfile_abort_trans(db->db);
		dbfile_unlock();
		return 0;
	}

	dbfile_commit_trans(db->db);
	dbfile_unlock();

	/* Schedule the file for scan */
	file = malloc(sizeof(struct file_to_scan)); /* Freed by csum_whole_file() */

	file->path = strdup(abspath);
	file->fileid = fileid;
	file->filesize = st.st_size;

	total_files_count++;
	file->file_position = total_files_count;

	if(!g_thread_pool_push(scan_pool.pool, file, &err)) {
		fprintf(stderr, "g_thread_pool_push: %s\n", err->message);
		g_error_free(err);
		err = NULL;
		free(file);
	}

	return 0;
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
			"Skipping.\n", ret, strerror(ret), file->path);
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
	struct stat st;
	lstat(path, &st);
	filerec_new(path, st.st_ino, 0, st.st_size);
}
