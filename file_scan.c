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

	/*
	 * The first call initializes the static variable
	 * from the global dedupe_seq
	 * The subsequents calls will increase it every <batchsize> times
	 */
	if (seq == 0)
		seq = dedupe_seq + 1;

	int fd = 0;
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
		close(fd);
		return 0;
	}

	if (options.run_dedupe == 1 &&
	    ((fs.f_type != BTRFS_SUPER_MAGIC &&
	      fs.f_type != XFS_SB_MAGIC))) {
		fprintf(stderr,	"\"%s\": Can only dedupe files on btrfs or xfs, "
			"use -d -d to override\n", abspath);
		close(fd);
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
			close(fd);
			return 0;
		}
	} else {
		subvolid = st.st_dev;
	}

	close(fd);

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
	ret = dbfile_store_file_info(db, st.st_ino, subvolid, abspath, st.st_size, timespec_to_nano(&(st.st_mtim)), seq);
	if (ret) {
		dbfile_abort_trans(db->db);
		dbfile_unlock();
		return 0;
	}

	dbfile_commit_trans(db->db);
	dbfile_unlock();

	/* Schedule the file for scan */
	file = malloc(sizeof(struct file_to_scan)); /* Freed by csum_whole_file() */

	file->path = strdup(abspath);
	file->ino = st.st_ino;
	file->subvolid = subvolid;

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

static inline int is_block_zeroed(void *buf, ssize_t buf_size)
{
	return buf && ((int*)buf)[0] == 0 && !memcmp(buf, buf + 1, buf_size - 1);
}

static int xlate_extent_flags(int fieflags, ssize_t len)
{
	int flags = 0;

	if (fieflags & FIEMAP_SKIP_FLAGS)
		flags |= FILE_BLOCK_SKIP_COMPARE;

	if (len < blocksize)
		flags |= FILE_BLOCK_PARTIAL;

	return flags;
}

static int add_block_hash(struct block_csum **hashes, uint64_t *nr_hashes,
			  uint64_t loff, unsigned char *digest, int flags)
{
	void *retp;
	struct block_csum *block_hashes;

	retp = realloc(*hashes, sizeof(struct block_csum) * (*nr_hashes + 1));
	if (!retp)
		return -ENOMEM;

	block_hashes = retp;
	block_hashes[*nr_hashes].loff = loff;
	block_hashes[*nr_hashes].flags = flags;
	memcpy(block_hashes[*nr_hashes].digest, digest, DIGEST_LEN);

	*hashes = retp;
	(*nr_hashes)++;
	return 0;
}

struct csum_ctxt {
	uint64_t blocks_recorded;
	char *buf;
	struct file_to_scan *file;
	unsigned char digest[DIGEST_LEN];

	struct block_csum *block_hashes;
	uint64_t nr_block_hashes;
	unsigned char block_digest[DIGEST_LEN];

	unsigned char file_digest[DIGEST_LEN];
};

static int csum_blocks(struct csum_ctxt *data, struct running_checksum *csum,
		       const uint64_t extoff, const ssize_t extlen, int flags,
		       struct running_checksum *file_csum)
{
	int ret = 0;
	int start = 0;
	ssize_t cmp_len = extlen - start;

	if (cmp_len > blocksize)
		cmp_len = blocksize;

	while (start < extlen) {
		char *buf = data->buf + start;

		if (!(options.skip_zeroes && is_block_zeroed(buf, cmp_len))) {
			checksum_block(buf, cmp_len, data->block_digest);

			if (options.do_block_hash) {
				ret = add_block_hash(&data->block_hashes,
						     &data->nr_block_hashes,
						     extoff + start,
						     data->block_digest,
						     flags);
				if (ret)
					break;
			}

			add_to_running_checksum(csum, DIGEST_LEN, data->block_digest);
			add_to_running_checksum(file_csum, DIGEST_LEN, data->block_digest);
		}

		start += cmp_len;
		cmp_len = extlen - start;
		if (cmp_len > blocksize)
			cmp_len = blocksize;
	}

	assert(start == extlen);

	return ret;

}

static int csum_extent(struct csum_ctxt *data, uint64_t extent_off,
		       uint64_t extent_len, int extent_flags,
		       uint64_t *ret_total_bytes_read,
		       struct running_checksum *file_csum)
{
	int ret = 0;
	int flags;
	uint64_t total_bytes_read = 0;
	struct running_checksum *csum;

	csum = start_running_checksum();
	if (!csum)
		return -1;

	while (total_bytes_read < extent_len) {
		ssize_t bytes_read = 0;
		size_t readlen = extent_len - total_bytes_read;
		if (readlen > READ_BUF_LEN)
			readlen = READ_BUF_LEN;

		ret = pread(data->file->fd, data->buf, readlen, extent_off);
		if (ret < 0) {
			ret = errno;
			fprintf(stderr, "Unable to read file %s: %s\n",
				data->file->path, strerror(ret));
			*ret_total_bytes_read = 0;
			return -ret;
		}
		if (ret == 0)
			break;

		bytes_read = ret;
		total_bytes_read += bytes_read;
		flags = xlate_extent_flags(extent_flags, bytes_read);

		ret = csum_blocks(data, csum, extent_off, bytes_read, flags, file_csum);
		if (ret)
			break;

		extent_off += bytes_read;
	}

	finish_running_checksum(csum, data->digest);

	*ret_total_bytes_read = total_bytes_read;
	ret = (total_bytes_read == 0) ? 0 : 1; // handle overflow
	return ret;
}

/*
 * Helper for csum_by_block/csum_by_extent.
 * Return < 0 on error, 0 on success and 1 if we find an extent that should not
 * be read.
 */
static int fiemap_helper(struct fiemap_ctxt *fc, int fd,
			 uint64_t *poff, uint64_t *loff, uint64_t *len,
			 unsigned int *flags)
{
	int ret;

	ret = fiemap_iter_next_extent(fc, fd, poff, loff, len, flags);
	if (ret)
		return ret;

	if ((options.skip_zeroes && *flags & FIEMAP_EXTENT_UNWRITTEN) ||
	    (*flags & FIEMAP_SKIP_FLAGS)) {
		/* Unwritten or other extent we don't want to read */
		return 1;
	}
	return 0;
}

static int get_file_extent_count(int fd, uint32_t *count)
{
	struct fiemap fiemap;
	int err;

	memset(&fiemap, 0, sizeof(fiemap));
	fiemap.fm_length = ~0ULL;
	err = ioctl(fd, FS_IOC_FIEMAP, (unsigned long) &fiemap);
	if (err < 0) {
		perror("fiemap failed");
		return errno;
	}

	dprintf("Got %u extent for file\n", fiemap.fm_mapped_extents);
	*count = fiemap.fm_mapped_extents;

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

static void csum_whole_file(struct file_to_scan *file)
{
	int ret = 0;
	uint64_t nb_hash = 0;
	_cleanup_(freep) struct fiemap_ctxt *fc = NULL;
	struct csum_ctxt csum_ctxt = {0,};

	_cleanup_(freep) struct extent_csum *extent_hashes = NULL;
	static struct dbhandle *db = NULL;
	static __thread char* buf = NULL;

	uint64_t poff, loff, bytes_read, len;
	uint32_t extents_count = 0;
	unsigned int flags;
	void *retp;
	struct block_csum *block_hashes = NULL;
	struct running_checksum *file_csum = NULL;

	print_progress(file->file_position, file->path);

	if (!buf) {
		buf = calloc(1, READ_BUF_LEN);
		assert(buf != NULL);

		register_cleanup(&scan_pool, (void*)&free, buf);
	}

	csum_ctxt.buf = buf;
	csum_ctxt.file = file;

	if(!db) {
		dbfile_lock();
		db = dbfile_open_handle(options.hashfile);
		dbfile_unlock();
		if (!db) {
			fprintf(stderr, "csum_whole_file: unable to connect to the database");
			goto err;
		}

		register_cleanup(&scan_pool, (void*)&dbfile_close_handle, db);
	}

	fc = alloc_fiemap_ctxt();
	if (fc == NULL) {
		fprintf(stderr,
			"Low memory allocating fiemap context for \"%s\"\n",
			file->path);
		goto err;
	}

	file->fd = open(file->path, O_RDONLY);
	if (file->fd == -1) {
		fprintf(stderr, "csum_whole_file: Error %d: %s while opening file \"%s\". "
			"Skipping.\n", ret, strerror(ret), file->path);
		goto err;
	}

	ret = get_file_extent_count(csum_ctxt.file->fd, &extents_count);
	if (ret) {
		fprintf(stderr, "Error: cannot get file extent count for %s\n", file->path);
		goto err;
	}

	extent_hashes = calloc(extents_count, sizeof(struct extent_csum));
	if (extent_hashes == NULL)
		goto err;

	block_hashes = malloc(sizeof(struct block_csum));
	if (block_hashes == NULL)
		goto err;

	csum_ctxt.block_hashes = block_hashes;

	file_csum = start_running_checksum();
	if (!file_csum)
		goto err;

	flags = 0;
	while (!(flags & FIEMAP_EXTENT_LAST)) {
		ret = fiemap_helper(fc, file->fd, &poff, &loff, &len, &flags);
		if (ret < 0) {
			fprintf(stderr, "Error %d from fiemap_helper()\n", ret);
			goto err;
		}

		if (ret == 1) {
			/* Skip reading this extent */
			continue;
		}

		ret = csum_extent(&csum_ctxt, loff, len, flags, &bytes_read, file_csum);
		if (ret == 0) /* EOF */
			break;

		if (ret < 0)  /* Err */ {
			fprintf(stderr, "Error %d from csum_extent()\n", ret);
			goto err;
		}

		if ((nb_hash + 1) > extents_count) {
			retp = realloc(extent_hashes,
				       sizeof(struct extent_csum) * (nb_hash + 1));
			if (!retp) {
				perror("csum_whole_file: realloc failed");
				goto err;
			}
			extent_hashes = retp;
		}

		extent_hashes[nb_hash].loff = loff;
		extent_hashes[nb_hash].poff = poff;
		extent_hashes[nb_hash].len = bytes_read;
		extent_hashes[nb_hash].flags = flags;
		memcpy(extent_hashes[nb_hash].digest, csum_ctxt.digest,
		       DIGEST_LEN);
		nb_hash++;

		csum_ctxt.blocks_recorded += (bytes_read + (blocksize - 1))/blocksize;
		if (bytes_read < len) {
			/* Partial read, don't get any more blocks */
			break;
		}
	}

	finish_running_checksum(file_csum, csum_ctxt.file_digest);
	file_csum = NULL;

	dbfile_lock();
	ret = dbfile_begin_trans(db->db);
	if (ret) {
		dbfile_unlock();
		goto err;
	}

	if (!options.only_whole_files) {
		if (options.do_block_hash) {
			ret = dbfile_store_block_hashes(db, file->ino, file->subvolid,
							csum_ctxt.nr_block_hashes,
							csum_ctxt.block_hashes);
			if (ret) {
				dbfile_abort_trans(db->db);
				dbfile_unlock();
				goto err;
			}
		}

		ret = dbfile_store_extent_hashes(db, file->ino, file->subvolid, nb_hash, extent_hashes);
		if (ret) {
			dbfile_abort_trans(db->db);
			dbfile_unlock();
			goto err;
		}
	}

	/* Do not store files with zero hashable extents. Those are
	 * usually small files inlined with extent type
	 * FIEMAP_EXTENT_DATA_INLINE. We avoid storing them as all these
	 * files have the same zero bytes checksum. Attempt to
	 * deduplicate those will never succeed and will produce a lot
	 * of needless work: https://github.com/markfasheh/duperemove/issues/316
	 */
	if (nb_hash > 0) {
		ret = dbfile_store_file_digest(db, file->ino, file->subvolid, csum_ctxt.file_digest);
		if (ret) {
			dbfile_abort_trans(db->db);
			dbfile_unlock();
			goto err;
		}
	}

	ret = dbfile_commit_trans(db->db);
	if (ret) {
		dbfile_unlock();
		goto err;
	}

	dbfile_unlock();

err:
	if (file_csum) {
		/* The output is worthless, this is only used to free memory */
		finish_running_checksum(file_csum, csum_ctxt.file_digest);
	}

	if (csum_ctxt.block_hashes)
		free(csum_ctxt.block_hashes);

	if (file->fd != -1)
		close(file->fd);
	free(file->path);
	free(file);
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
