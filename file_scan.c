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

/* This is not in linux/magic.h */
#ifndef	XFS_SB_MAGIC
#define	XFS_SB_MAGIC		0x58465342	/* 'XFSB' */
#endif

static char path[PATH_MAX] = { 0, };
static char *pathp = path;
static char *path_max = &path[PATH_MAX - 1];
static dev_t one_fs_dev;
static uint64_t one_fs_btrfs;

static uint64_t walked_size;
static unsigned long long files_to_scan;
static GMutex io_mutex; /* locks db writes */
static unsigned int leading_spaces;

#define READ_BUF_LEN (8*1024*1024) // 8MB

struct thread_params {
	GMutex mutex;
	unsigned long long num_files;  /* Total number of files we hashed */
	unsigned long long num_hashes; /* Total number of hashes we hashed */
	struct dbfile_config	*dbfile_cfg; /* global dbfile config */
};

extern struct dbfile_config dbfile_cfg;
extern bool rescan_files;
extern bool only_whole_files;
LIST_HEAD(exclude_list);

extern bool do_block_hash;

static void set_filerec_scan_flags(struct filerec *file)
{
	if (!(file->flags & FILEREC_NEEDS_SCAN)) {
		file->flags |= FILEREC_NEEDS_SCAN;
		files_to_scan++;
	}
	file->flags |= FILEREC_UPDATE_DB;
}

static void clear_filerec_scan_flags(struct filerec *file)
{
	if (file->flags & FILEREC_NEEDS_SCAN) {
		file->flags &= ~FILEREC_NEEDS_SCAN;
		files_to_scan--;
	}
	file->flags &= ~FILEREC_UPDATE_DB;
}

dev_t fs_onefs_dev(void)
{
	return one_fs_dev;
}

uint64_t fs_onefs_id(void)
{
	return one_fs_btrfs;
}

static int get_dirent_type(struct dirent *entry, int fd)
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

static int walk_dir(const char *name)
{
	int ret = 0;
	int type;
	struct dirent *entry;
	DIR *dirp;

	dirp = opendir(path);
	if (dirp == NULL) {
		fprintf(stderr, "Error %d: %s while opening directory %s\n",
			errno, strerror(errno), name);
		return 0;
	}

	do {
		errno = 0;
		entry = readdir(dirp);
		if (entry) {
			if (strcmp(entry->d_name, ".") == 0
			    || strcmp(entry->d_name, "..") == 0)
				continue;

			type = get_dirent_type(entry, dirfd(dirp));
			if (type == DT_REG ||
			    (recurse_dirs && type == DT_DIR)) {
				if (add_file(entry->d_name)) {
					ret = 1;
					goto out;
				}
			}
		}
	} while (entry != NULL);

	if (errno) {
		fprintf(stderr, "Error %d: %s while reading directory %s\n",
			errno, strerror(errno), path);
	}

out:
	closedir(dirp);
	return ret;
}

static int __add_file(const char *name, struct stat *st,
		      struct filerec **ret_file)
{
	int ret;
	int fd;
	struct filerec *file;
	uint64_t subvolid;
	struct statfs fs;

	if (S_ISDIR(st->st_mode))
		return 0;

	if (!S_ISREG(st->st_mode)) {
		vprintf("Skipping non-regular file %s\n", name);
		return 0;
	}

	ret = access(name, R_OK);
	if (ret) {
		fprintf(stderr, "Error %d: %s while accessing file %s. "
			"Skipping.\n",
			errno, strerror(errno), name);
		goto out;
	}

	fd = open(name, O_RDONLY);
	if (fd == -1) {
		ret = errno;
		fprintf(stderr, "Error %d: %s while opening file \"%s\". "
			"Skipping.\n", ret, strerror(ret), name);
		goto out;
	}

	ret = fstatfs(fd, &fs);
	if (ret) {
		close(fd);
		fprintf(stderr, "Error %d: %s while doing fs stat on \"%s\". "
			"Skipping.\n", ret, strerror(ret), name);
		goto out;
	}

	if (is_excluded(name))
		return 0;

	if (run_dedupe == 1 &&
	    ((fs.f_type != BTRFS_SUPER_MAGIC &&
	      fs.f_type != XFS_SB_MAGIC))) {
		close(fd);
		fprintf(stderr,	"\"%s\": Can only dedupe files on btrfs or xfs, "
			"use -d -d to override\n", name);
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
			close(fd);
			fprintf(stderr,
				"Error %d: %s while finding subvolid for file "
				"\"%s\". Skipping.\n", ret, strerror(ret),
				name);
			goto out;
		}
	} else {
		subvolid = st->st_dev;
	}

//	printf("\"%s\", ino: %llu, subvolid: %"PRIu64"\n", name,
//	       (unsigned long long)st->st_ino, subvolid);

	close(fd);

	walked_size += st->st_size;

	file = filerec_find(st->st_ino, subvolid);
	if (!file)
		file = filerec_new(name, st->st_ino, subvolid, st->st_size,
				   timespec_to_nano(&st->st_mtim));

	if (file == NULL) {
		fprintf(stderr, "Out of memory while allocating file record "
			"for: %s\n", name);
		return ENOMEM;
	}
	if (ret_file)
		*ret_file = file;

	return 0;

out:
	return 1;
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
int add_file(const char *name)
{
	int ret, len = strlen(name);
	struct stat st;
	char *pathtmp;
	struct filerec *file = NULL;
	char abspath[PATH_MAX];
	uint64_t mtime = 0, size = 0;

	if (len > (path_max - pathp)) {
		fprintf(stderr, "Path max exceeded: %s %s\n", path, name);
		return 0;
	}

	pathtmp = pathp;
	if (pathp == path)
		ret = sprintf(pathp, "%s", name);
	else
		ret = sprintf(pathp, "/%s", name);
	pathp += ret;

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
		goto out;
	}

	ret = lstat(abspath, &st);
	if (ret) {
		fprintf(stderr, "Error %d: %s while stating file %s. "
			"Skipping.\n",
			errno, strerror(errno), abspath);
		goto out;
	}

	if (S_ISDIR(st.st_mode)) {
		uint64_t btrfs_fsid;
		dev_t dev = st.st_dev;

		if (is_excluded(abspath))
			goto out;

		/*
		 * Device doesn't work for btrfs as it changes between
		 * subvolumes. We know how to get a unique fsid though
		 * so use that in the case where we are on btrfs.
		 */
		ret = check_btrfs_get_fsid(abspath, &btrfs_fsid);
		if (ret) {
			vprintf("Skipping directory %s due to error %d: %s\n",
				abspath, ret, strerror(ret));
			goto out;
		}

		/* Don't cross mount points since dedup doesn't work across */
		if (will_cross_mountpoint(dev, btrfs_fsid)) {
			vprintf("Mountpoint traversal disallowed: %s \n",
				abspath);
			goto out;
		}

		if (walk_dir(name))
			return 1;
		goto out;
	}

	/*
	 * Since we scan the disk via stat() first, we should never
	 * get a duplicate filename at this stage. However we can
	 * still check to be safe as the result will otherwise be an
	 * abort in the insert routine.
	 * On the other hand, this check enforces hardlinks detection.
	 */
	if (filerec_find_by_name(abspath)) {
		vprintf("Filename \"%s\" was seen twice! Skipping.\n", abspath);
		goto out;
	}

	ret = __add_file(abspath, &st, &file);
	if (ret)
		return ret;

	/* File has been excluded by _add_file() */
	if (!file)
		goto out;

	/*
	 * Check the database to see if that file need rescan or not.
	 */
	ret = dbfile_describe_file(dbfile_get_handle(), file->inum, file->subvolid, &mtime, &size);
	if (ret) {
		vprintf("dbfile_describe_file failed\n");
		goto out;
	}

	if (mtime != file->mtime || size != file->size)
		set_filerec_scan_flags(file);

	if (mtime != 0 || size != 0)
		file->flags |= FILEREC_IN_DB;

out:
	pathp = pathtmp;
	return 0;
}

#define	print_file_changed(_filename, _inum, _subvolid, _file)		\
	do {								\
		vprintf("Database record (\"%s\", %"PRIu64".%"PRIu64") "\
			"differs from disk (\"%s\", %"PRIu64".%"PRIu64	\
			"), update flagged.\n", _filename, _inum,	\
			_subvolid, (_file)->filename, (_file)->inum,	\
			(_file)->_subvolid);				\
	} while (0)

/*
 * Add filerec from a db record.
 *
 * If we find a filerec in our ino/subvol hash, compare against db
 * info and update flags as necessary:
 *
 * * The filerec is marked to be updated in the db if size or mtime changed.
 * * The filerec is marked for rehash if mtime changed.
 *
 * If no filerec, we stat based on db filename:
 *
 * * If we don't find it (ENOENT), or subvol/inode has changed, mark
 *   the db record for deletion.
 *
 * Otherwise a filerec gets added based on the stat'd information.
 */
int add_file_db(const char *filename, uint64_t inum, uint64_t subvolid,
		uint64_t size, uint64_t mtime, unsigned int seq, int *delete)
{
	int ret = 0;
	struct filerec *file = filerec_find(inum, subvolid);
	struct stat st;

	*delete = 0;

	dprintf("Lookup/stat file \"%s\" from hashdb\n", filename);

	if (!file) {
		file = filerec_find_by_name(filename);
		if (file) {
			/*
			 * We have a file by this name but a different
			 * inode number. Delete the record and allow
			 * scan to put the correct one in.
			 */
			file->dedupe_seq = seq;
			print_file_changed(filename, inum, subvolid, file);
			set_filerec_scan_flags(file);
			*delete = 1;
			return 0;
		}
		/* Go to disk and look up by filename */
		ret = lstat(filename, &st);
		if (ret == -1 && errno == ENOENT) {
			vprintf("File path %s no longer exists. Skipping.\n",
				filename);
			*delete = 1;
			return 0;
		} else if (ret == -1) {
			fprintf(stderr,	"Error %d: %s while stating file %s.\n",
				errno, strerror(errno), filename);
			*delete = 1;
			return 0;
		}

		ret = __add_file(filename, &st, &file);
		if (ret)
			return ret;

		if (!file) {
			/*
			 * File is in DB and on disk but _add_file()
			 * didn't like it (could be too small now,
			 * mode change, etc).
			 */
			*delete = 1;
			return 0;
		}
	}
	/*
	 * Set dedupe_seq from the db record. It will be updated if we
	 * mark the file for rescan.
	 */
	file->dedupe_seq = seq;

	clear_filerec_scan_flags(file);
	if (mtime != file->mtime || size != file->size) {
		set_filerec_scan_flags(file);
		file->flags |= FILEREC_UPDATE_DB;
	}

	if (file->inum != inum || file->subvolid != subvolid ||
	    strcmp(filename, file->filename)) {
		print_file_changed(filename, inum, subvolid, file);
		set_filerec_scan_flags(file);
		*delete = 1;
	} else {
		/* All 3 of (filename, ino, subvol) match */
		file->flags |= FILEREC_IN_DB;
	}

	return 0;
}

static GThreadPool *setup_pool(void *arg, void *function)
{
	GError *err = NULL;
	GThreadPool *pool;

	pool = g_thread_pool_new((GFunc) function, arg, io_threads, FALSE,
				 &err);
	if (err != NULL) {
		fprintf(stderr, "Unable to create thread pool: %s\n",
			err->message);
		g_error_free(err);
		err = NULL;
		return NULL;
	}
	return pool;
}

static void run_pool(GThreadPool *pool, struct filerec *file,
		unsigned int batch_size)
{
	GError *err = NULL;
	struct filerec *tmp;

	unsigned int counter = 0;

	qprintf("Using %u threads for file hashing phase\n", io_threads);

	/* Reset the scanned filerecs */
	list_for_each_entry(file, &filerec_list, rec_list) {
		file->scanned = false;
	}

	list_for_each_entry_safe(file, tmp, &filerec_list, rec_list) {
		if (file->flags & FILEREC_NEEDS_SCAN) {
			file->scanned = true;
			g_thread_pool_push(pool, file, &err);
			if (err != NULL) {
				fprintf(stderr,
					"g_thread_pool_push: %s\n",
					err->message);
				g_error_free(err);
				err = NULL;
			}

			/* If batch_size is 0 then batching is disabled */
			if ( batch_size != 0 ) {
				counter += 1;
				if (counter > batch_size) {
					break;
				}
			}
		}
	}

	g_thread_pool_free(pool, FALSE, TRUE);
}

static inline int is_block_zeroed(void *buf, ssize_t buf_size)
{
	return !(buf && memcmp(buf, buf + 1, buf_size - 1));
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
	struct filerec *file;
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

		if (!(skip_zeroes && is_block_zeroed(buf, cmp_len))) {
			checksum_block(buf, cmp_len, data->block_digest);

			if (do_block_hash) {
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
				data->file->filename, strerror(ret));
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

static void csum_whole_file_init(struct filerec *file,
				 struct fiemap_ctxt **fc)
{
	static long long unsigned _cur_scan_files;
	unsigned long long cur_scan_files;

	cur_scan_files = __atomic_add_fetch(&_cur_scan_files, 1, __ATOMIC_SEQ_CST);

	qprintf("[%0*llu/%llu] (%05.2f%%) csum: %s\n",
		leading_spaces, cur_scan_files, files_to_scan,
		(double)cur_scan_files / (double)files_to_scan * 100,
		file->filename);

	*fc = alloc_fiemap_ctxt();
	if (*fc == NULL) /* This should be non-fatal */
		fprintf(stderr,
			"Low memory allocating fiemap context for \"%s\"\n",
			file->filename);
}

/*
 * Helper for csum_by_block/csum_by_extent.
 * Return < 0 on error, 0 on success and 1 if we find an extent that should not
 * be read.
 */
static int fiemap_helper(struct fiemap_ctxt *fc, struct filerec *file,
			 uint64_t *poff, uint64_t *loff, uint64_t *len,
			 unsigned int *flags)
{
	int ret;

	ret = fiemap_iter_next_extent(fc, file, poff, loff, len, flags);
	if (ret)
		return ret;

	if ((skip_zeroes && *flags & FIEMAP_EXTENT_UNWRITTEN) ||
	    (*flags & FIEMAP_SKIP_FLAGS)) {
		/* Unwritten or other extent we don't want to read */
		return 1;
	}
	return 0;
}

static int get_file_extent_count(struct filerec *file, uint32_t *count)
{
	struct fiemap fiemap;
	int err;

	memset(&fiemap, 0, sizeof(fiemap));
	fiemap.fm_length = ~0ULL;
	err = ioctl(file->fd, FS_IOC_FIEMAP, (unsigned long) &fiemap);
	if (err < 0)
		return errno;

	dprintf("Got %u extent for file\n", fiemap.fm_mapped_extents);
	*count = fiemap.fm_mapped_extents;

	return 0;
}

static int csum_by_extent(struct csum_ctxt *ctxt, struct fiemap_ctxt *fc,
			  struct extent_csum **ret_extent_hashes,
			  uint64_t *ret_nb_hash)
{
	uint64_t poff, loff, bytes_read, len;
	uint32_t extents_count = 0;
	int ret = 0;
	unsigned int flags;
	struct extent_csum *extent_hashes;
	void *retp;
	struct filerec *file = ctxt->file;
	uint64_t nb_hash = 0;
	struct block_csum *block_hashes;
	struct running_checksum *file_csum;
//	int nb_block_hash = 0;

	ret = get_file_extent_count(file, &extents_count);
	if (ret)
		return ret;

	extent_hashes = calloc(extents_count, sizeof(struct extent_csum));
	if (extent_hashes == NULL)
		return ENOMEM;

	block_hashes = malloc(sizeof(struct block_csum));
	if (block_hashes == NULL) {
		free(extent_hashes);
		return ENOMEM;
	}

	/* We require fiemap to do dedupe by extent. */
	if (fc == NULL) {
		free(extent_hashes);
		free(block_hashes);
		return ENOMEM;
	}

	ctxt->block_hashes = block_hashes;

	file_csum = start_running_checksum();
	if (!file_csum)
		return 1;

	flags = 0;
	while (!(flags & FIEMAP_EXTENT_LAST)) {
		ret = fiemap_helper(fc, file, &poff, &loff, &len, &flags);
		if (ret < 0) {
			fprintf(stderr, "Error %d from fiemap_helper()\n", ret);
			goto out;
		}

		if (ret == 1) {
			/* Skip reading this extent */
			continue;
		}

		ret = csum_extent(ctxt, loff, len, flags, &bytes_read, file_csum);
		if (ret == 0) /* EOF */
			break;

		if (ret < 0)  /* Err */ {
			fprintf(stderr, "Error %d from csum_extent()\n", ret);
			goto out;
		}

		if ((nb_hash + 1) > extents_count) {
			retp = realloc(extent_hashes,
				       sizeof(struct extent_csum) * (nb_hash + 1));
			if (!retp) {
				ret = ENOMEM;
				goto out;
			}
			extent_hashes = retp;
		}

//		printf("loff %"PRIu64" ret %d len %u flags 0x%x\n",
//		       loff, ret, len, flags);
		extent_hashes[nb_hash].loff = loff;
		extent_hashes[nb_hash].poff = poff;
		/* XXX: put len or actual read length in here? */
//		extent_hashes[nb_hash].len = len;
		extent_hashes[nb_hash].len = bytes_read;
		extent_hashes[nb_hash].flags = flags;
		memcpy(extent_hashes[nb_hash].digest, ctxt->digest,
		       DIGEST_LEN);
		nb_hash++;

		ctxt->blocks_recorded += (bytes_read + (blocksize - 1))/blocksize;
		if (bytes_read < len) {
			/* Partial read, don't get any more blocks */
			break;
		}
	}

	finish_running_checksum(file_csum, ctxt->file_digest);

	ret = 0;
	*ret_nb_hash = nb_hash;
	*ret_extent_hashes = extent_hashes;
out:
	if (ret && extent_hashes)
		free(extent_hashes);

	return ret;
}

static void csum_whole_file(struct filerec *file,
			    struct thread_params *params)
{
	int ret = 0;
	uint64_t nb_hash = 0;
	struct fiemap_ctxt *fc = NULL;
	struct csum_ctxt csum_ctxt;
	struct sqlite3 *db = NULL;
	struct extent_csum *extent_hashes = NULL;
	struct block_csum *block_hashes = NULL;

	memset(&csum_ctxt, 0, sizeof(csum_ctxt));
	csum_ctxt.buf = calloc(1, READ_BUF_LEN);
	assert(csum_ctxt.buf != NULL);
	csum_ctxt.file = file;

	csum_whole_file_init(file, &fc);

	db = dbfile_get_handle();
	if (!db)
		goto err_noclose;

	ret = filerec_open(file);
	if (ret)
		goto err_noclose;

	ret = csum_by_extent(&csum_ctxt, fc, &extent_hashes, &nb_hash);
	if (ret)
		goto err;

	g_mutex_lock(&io_mutex);
	file->num_blocks = csum_ctxt.blocks_recorded;
	/* Make sure that we'll check this file on any future dedupe passes */
	filerec_clear_deduped(file);
	ret = dbfile_begin_trans(db);
	if (ret) {
		g_mutex_unlock(&io_mutex);
		goto err;
	}

	ret = dbfile_store_file_info(db, file);
	if (ret) {
		g_mutex_unlock(&io_mutex);
		goto err;
	}

	if (!only_whole_files) {
		if (do_block_hash) {
			ret = dbfile_store_block_hashes(db, file,
							csum_ctxt.nr_block_hashes,
							csum_ctxt.block_hashes);
			if (ret) {
				g_mutex_unlock(&io_mutex);
				goto err;
			}
		}

		ret = dbfile_store_extent_hashes(db, file, nb_hash, extent_hashes);
		if (ret) {
			g_mutex_unlock(&io_mutex);
			goto err;
		}
	}

	ret = dbfile_store_file_digest(db, file, csum_ctxt.file_digest);
	if (ret) {
		g_mutex_unlock(&io_mutex);
		goto err;
	}

	ret = dbfile_commit_trans(db);
	if (ret) {
		g_mutex_unlock(&io_mutex);
		goto err;
	}
	g_mutex_unlock(&io_mutex);

	g_mutex_lock(&params->mutex);
	params->num_files++;
	params->num_hashes += nb_hash;
	g_mutex_unlock(&params->mutex);

	file->flags &= ~(FILEREC_NEEDS_SCAN|FILEREC_UPDATE_DB);
	/* Set 'IN_DB' flag *after* we call dbfile_store_hashes() */
	file->flags |= FILEREC_IN_DB;

	filerec_close(file);
	free(csum_ctxt.buf);
	if (fc)
		free(fc);
	if (csum_ctxt.block_hashes)
		free(csum_ctxt.block_hashes);

	free(extent_hashes);
	return;

err:
	g_mutex_lock(&params->mutex);
	params->num_files++;
	g_mutex_unlock(&params->mutex);

	filerec_close(file);
err_noclose:
	free(csum_ctxt.buf);
	if (extent_hashes)
		free(extent_hashes);
	if (block_hashes)
		free(block_hashes);
	if (csum_ctxt.block_hashes)
		free(csum_ctxt.block_hashes);
	if (fc)
		free(fc);

	fprintf(
		stderr,
		"Skipping file due to error %d from function csum_by_extent (%s), %s\n",
		ret,
		strerror(ret),
		file->filename);

	g_mutex_lock(&params->mutex);
	/*
	 * filerec_free will remove from the filerec tree keep it
	 * under tree_mutex until we have a need for real locking in
	 * filerec.c
	 */
	filerec_free(file);
	g_mutex_unlock(&params->mutex);

	return;
}

int populate_tree(struct dbfile_config *cfg, unsigned int batch_size,
		void (*callback)(void))
{
	GThreadPool *pool;
	struct thread_params params;
	int ret = 0;

	struct filerec *file = NULL;

	g_mutex_init(&params.mutex);
	params.dbfile_cfg = cfg;
	params.num_files = params.num_hashes = 0;

	leading_spaces = num_digits(files_to_scan);

	if (files_to_scan) {
		while (params.num_files != files_to_scan) {
			pool = setup_pool(&params, csum_whole_file);
			if (!pool) {
				ret = ENOMEM;
				goto out;
			}

			run_pool(pool, file, batch_size);
			callback();
		}

		printf("Total files scanned:  %llu\n", params.num_files);
		qprintf("Total extent hashes scanned: %llu\n", params.num_hashes);
	} else {
		// Maybe some files where scanned in a previous run but never
		// deduped
		callback();
	}
out:
	g_mutex_clear(&params.mutex);
	return ret;
}
