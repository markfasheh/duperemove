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
#include <inttypes.h>
#include <linux/magic.h>
#include <sys/statfs.h>

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

struct thread_params {
	int num_files;           /* Total number of files we hashed */
	int num_hashes;          /* Total number of hashes we hashed */
};

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

void fs_set_onefs(dev_t dev, uint64_t fsid)
{
	if (dev || fsid) {
		one_file_system = 1;
		if (dev)
			one_fs_dev = dev;
		else if (fsid)
			one_fs_btrfs = fsid;
	}
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
	ret = fstatat(fd, entry->d_name, &st, 0);
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
				if (add_file(entry->d_name, dirfd(dirp))) {
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
		goto out;

	if (!S_ISREG(st->st_mode)) {
		vprintf("Skipping non-regular file %s\n", name);
		goto out;
	}

	if (st->st_size < blocksize) {
		vprintf("Skipping small file %s\n", name);
		goto out;
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

	if (run_dedupe &&
	    ((fs.f_type != BTRFS_SUPER_MAGIC &&
	      fs.f_type != XFS_SB_MAGIC))) {
		close(fd);
		fprintf(stderr,	"\"%s\": Can only dedupe files on btrfs or xfs "
			"(experimental)\n", name);
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
	file = filerec_new(name, st->st_ino, subvolid, st->st_size,
			   timespec_to_nano(&st->st_mtim));
	if (file == NULL) {
		fprintf(stderr, "Out of memory while allocating file record "
			"for: %s\n", name);
		return ENOMEM;
	}
	if (ret_file)
		*ret_file = file;
out:
	return 0;
}

/*
 * Returns nonzero on fatal errors only
 */
int add_file(const char *name, int dirfd)
{
	int ret, len = strlen(name);
	struct stat st;
	char *pathtmp;
	dev_t dev;
	struct filerec *file = NULL;
	char abspath[PATH_MAX];
	uint64_t btrfs_fsid;

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

	ret = stat(abspath, &st);
	if (ret) {
		fprintf(stderr, "Error %d: %s while stating file %s. "
			"Skipping.\n",
			errno, strerror(errno), abspath);
		goto out;
	}

	if (S_ISDIR(st.st_mode)) {
		dev = st.st_dev;
		/*
		 * Device doesn't work for btrfs as it changes between
		 * subvolumes. We know how to get a unique fsid though
		 * so use that in the case where we are on btrfs.
		 */
		ret = check_btrfs_get_fsid(abspath, &st, &btrfs_fsid);
		if (ret) {
			vprintf("Skipping directory %s due to error %d: %s\n",
				abspath, ret, strerror(ret));
			goto out;
		}

		if (one_file_system) {
			abort_on(one_fs_dev && one_fs_btrfs);

			if (!one_fs_dev && !one_fs_btrfs) {
				if (btrfs_fsid)
					one_fs_btrfs = btrfs_fsid;
				else
					one_fs_dev = dev;
			}

			if ((one_fs_dev && (one_fs_dev != dev)) ||
			    (one_fs_btrfs && (btrfs_fsid != one_fs_btrfs))) {
				vprintf("Skipping file %s because of -x\n",
					abspath);
				goto out;
			}
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
	 */
	if (filerec_find_by_name(abspath)) {
		vprintf("Filename \"%s\" was seen twice! Skipping.\n", abspath);
		goto out;
	}

	ret = __add_file(abspath, &st, &file);
	if (ret)
		return ret;

	/*
	 * We run the file scan before the database. Mark each file as
	 * needing a db update plus rescan. Later, when we run the DB
	 * we will conditionally clear these flags on already-seen
	 * inodes.
	 */
	if (file)
		set_filerec_scan_flags(file);

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
		ret = stat(filename, &st);
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
	if (mtime != file->mtime)
		set_filerec_scan_flags(file);
	else if (size != file->size) /* size change alone means no alloc */
		file->flags |= FILEREC_UPDATE_DB;

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

static GThreadPool *setup_pool(void *location, GMutex *mutex,
			void *function)
{
	GError *err = NULL;
	GThreadPool *pool;

	g_mutex_init(mutex);
	g_dataset_set_data_full(location, "mutex", mutex,
				(GDestroyNotify) g_mutex_clear);

	pool = g_thread_pool_new((GFunc) function, location, io_threads,
				 FALSE, &err);
	if (err != NULL) {
		fprintf(
			stderr,
			"Unable to create thread pool: %s\n",
			err->message);
		g_error_free(err);
		err = NULL;
		g_dataset_destroy(location);
		return NULL;
	}
	return pool;
}

static void run_pool(GThreadPool *pool)
{
	GError *err = NULL;
	struct filerec *file, *tmp;

	printf("Using %u threads for file hashing phase\n", io_threads);

	list_for_each_entry_safe(file, tmp, &filerec_list, rec_list) {
		if (file->flags & FILEREC_NEEDS_SCAN) {
			g_thread_pool_push(pool, file, &err);
			if (err != NULL) {
				fprintf(stderr,
					"g_thread_pool_push: %s\n",
					err->message);
				g_error_free(err);
				err = NULL;
			}
		}
	}

	g_thread_pool_free(pool, FALSE, TRUE);
}

static inline int is_block_zeroed(void *buf, ssize_t buf_size)
{
	/*
	 * If buf is block aligned check for zeroes may be accelerated
	 * By checks block by CPU word size
	 */
	if (buf_size%sizeof(ssize_t) == 0) {
		ssize_t *buf_start = buf;
		ssize_t *buf_end = buf+buf_size;
		ssize_t *ptr = buf_start;
		for (; ptr < buf_end; ptr++) {
			if (*ptr != 0)
				return 0;
		}
	} else {
		char *buf_start = buf;
		char *buf_end = buf+buf_size;
		char *ptr = buf_start;
		for (; ptr < buf_end; ptr++) {
			if (*ptr != 0)
				return 0;
		}
	}
	return 1;
}

struct csum_block {
	ssize_t bytes;
	unsigned int flags;
	char *buf;
	struct filerec *file;
	unsigned char digest[DIGEST_LEN_MAX];
};

static inline int csum_next_block(struct csum_block *data, uint64_t *off,
				  struct fiemap_ctxt **in_fc)
{
	struct fiemap_ctxt *fc = NULL;
	ssize_t stored_bytes = data->bytes;
	ssize_t bytes_read;
	int ret = 0;
	unsigned int hole;
	int partial = 0;

	if (in_fc)
		fc = *in_fc;

	bytes_read = read(data->file->fd, data->buf + stored_bytes,
				blocksize - stored_bytes);
	if (bytes_read < 0) {
		ret = errno;
		fprintf(stderr, "Unable to read file %s: %s\n",
			data->file->filename, strerror(ret));
		return -1;
	}

	/* Handle EOF */
	if (bytes_read == 0)
		return 0;

	data->bytes += bytes_read;

	/* Handle partial read */
	if (bytes_read < blocksize) {
		/*
		 * Don't want to store the len of each block, so
		 * hash-tree makes the assumption that a partial block
		 * is the last one.
		 */
		if (bytes_read + *off != data->file->size)
			return -1;
		partial = FILE_BLOCK_PARTIAL;
	}
	data->flags = hole = partial;
	if (fc) {
		unsigned int fieflags = 0;

		ret = fiemap_iter_get_flags(fc, data->file, *off, &fieflags,
					    &hole);
		if (ret) {
			fprintf(stderr,
				"Fiemap error %d while scanning file "
				"\"%s\": %s\n", ret, data->file->filename,
				strerror(ret));

			free(fc);
			fc = *in_fc = NULL;
		} else {
			if (skip_zeroes && fieflags & FIEMAP_EXTENT_UNWRITTEN)
				return 3;
			if (hole)
				return 3;
			if (fieflags & FIEMAP_SKIP_FLAGS)
				data->flags |= FILE_BLOCK_SKIP_COMPARE;
		}
	}

	if (skip_zeroes && is_block_zeroed(data->buf, data->bytes))
		return 3;

	checksum_block(data->buf, data->bytes, data->digest);
	if (data->flags & FILE_BLOCK_PARTIAL)
		return 1;
	return 2;
}

static void csum_whole_file_init(GMutex **mutex, void *location,
				struct filerec *file, struct fiemap_ctxt **fc)
{
	static long long unsigned _cur_scan_files;
	unsigned long long cur_scan_files;
	*mutex = g_dataset_get_data(location, "mutex");

	cur_scan_files = __sync_add_and_fetch(&_cur_scan_files, 1);

	printf("[%0*llu/%llu] (%05.2f%%) csum: %s\n",
	       leading_spaces, cur_scan_files, files_to_scan,
	       (double)cur_scan_files / (double)files_to_scan * 100,
	       file->filename);

	if (do_lookup_extents) {
		*fc = alloc_fiemap_ctxt();
		if (*fc == NULL) /* This should be non-fatal */
			fprintf(stderr,
				"Low memory allocating fiemap context for \"%s\"\n",
				file->filename);
	}
}

static void csum_whole_file(struct filerec *file,
			    struct thread_params *params)
{
	uint64_t off = 0;
	int ret = 0;
	struct fiemap_ctxt *fc = NULL;
	struct csum_block curr_block;
	struct sqlite3 *db = NULL;

	curr_block.buf = malloc(blocksize);
	assert(curr_block.buf != NULL);
	curr_block.file = file;
	curr_block.bytes = 0;

	struct block *hashes = malloc(sizeof(struct block));
	void *retp;
	int nb_hash = 0;

	GMutex *mutex;

	csum_whole_file_init(&mutex, params, file, &fc);

	if (hashes == NULL) {
		ret = ENOMEM;
		goto err_noclose;
	}

	db = dbfile_get_handle();
	if (!db)
		goto err_noclose;

	ret = filerec_open(file, 0);
	if (ret)
		goto err_noclose;

	while (1) {
		ret = csum_next_block(&curr_block, &off, &fc);
		if (ret == 0) /* EOF */
			break;

		if (ret == -1) /* Err */
			goto err;

		if (ret == 3) { /* Skip block */
			off += curr_block.bytes;
			curr_block.bytes = 0;
			continue;
		}


		retp = realloc(hashes, sizeof(struct block) * (nb_hash + 1));
		if (!retp) {
			ret = ENOMEM;
			goto err;
		}
		hashes = retp;

		hashes[nb_hash].loff = off;
		hashes[nb_hash].flags = curr_block.flags;
		memcpy(hashes[nb_hash].digest, curr_block.digest,
					DIGEST_LEN_MAX);
		nb_hash++;

		if (ret == 1) /* Partial read, don't get any more blocks */
			break;

		off += curr_block.bytes;
		curr_block.bytes = 0;
	}

	g_mutex_lock(&io_mutex);
	file->num_blocks = nb_hash;
	/* Make sure that we'll check this file on any future dedupe passes */
	filerec_clear_deduped(file);
	ret = dbfile_begin_trans(db);
	if (ret) {
		g_mutex_unlock(&io_mutex);
		goto err;
	}

	ret = dbfile_write_file_info(db, file);
	if (ret) {
		g_mutex_unlock(&io_mutex);
		goto err;
	}

	ret = dbfile_write_hashes(db, file, nb_hash, hashes);
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

	g_mutex_lock(mutex);
	params->num_files++;
	params->num_hashes += nb_hash;
	g_mutex_unlock(mutex);

	file->flags &= ~(FILEREC_NEEDS_SCAN|FILEREC_UPDATE_DB);
	/* Set 'IN_DB' flag *after* we call dbfile_write_hashes() */
	file->flags |= FILEREC_IN_DB;

	filerec_close(file);
	free(curr_block.buf);
	if (fc)
		free(fc);

	free(hashes);
	return;

err:
	filerec_close(file);
err_noclose:
	free(curr_block.buf);
	if (hashes)
		free(hashes);
	if (fc)
		free(fc);

	fprintf(
		stderr,
		"Skipping file due to error %d (%s), %s\n",
		ret,
		strerror(ret),
		file->filename);

	g_mutex_lock(mutex);
	/*
	 * filerec_free will remove from the filerec tree keep it
	 * under tree_mutex until we have a need for real locking in
	 * filerec.c
	 */
	filerec_free(file);
	g_mutex_unlock(mutex);

	return;
}

int populate_tree()
{
	GMutex mutex;
	GThreadPool *pool;
	struct thread_params params = { 0, 0, };

	leading_spaces = num_digits(files_to_scan);

	if (files_to_scan) {
		pool = setup_pool(&params, &mutex, csum_whole_file);
		if (!pool)
			return ENOMEM;

		run_pool(pool);

		printf("Total files:  %d\n", params.num_files);
		printf("Total hashes: %d\n", params.num_hashes);

		g_dataset_destroy(&params);
	}

	return 0;
}
