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

#include <glib.h>

#include "csum.h"
#include "list.h"
#include "filerec.h"
#include "hash-tree.h"
#include "btrfs-util.h"
#include "debug.h"
#include "serialize.h"
#include "file_scan.h"
#include "bloom.h"

static char path[PATH_MAX] = { 0, };
static char *pathp = path;
static char *path_max = &path[PATH_MAX - 1];
static dev_t one_fs_dev = 0;

static uint64_t walked_size = 0;

struct thread_params {
	struct hash_tree *tree; /* Contains all hashes (all-in-memory path)
				 * or just the "dups" hashes (swap-file path
				 */
	int num_files;		/* Total number of files we hashe */
	int num_hashes;		/* Total number of hashes we hashed */
	unsigned int bloom_match; /* Total number of matched by bloom */
	int hfile;		/* fd to the swap-file, or -1 if none */
	struct bloom bloom;	/* the real bloom filter */
};

static int walk_dir(const char *name)
{
	int ret = 0;
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

			if (entry->d_type == DT_REG ||
			    (recurse_dirs && entry->d_type == DT_DIR))
				if (add_file(entry->d_name, dirfd(dirp))) {
					ret = 1;
					goto out;
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

/*
 * Returns nonzero on fatal errors only
 */
int add_file(const char *name, int dirfd)
{
	int ret, len = strlen(name);
	int fd;
	int on_btrfs = 0;
	struct stat st;
	char *pathtmp;
	struct filerec *file;
	uint64_t subvolid;
	dev_t dev;

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

	ret = fstatat(dirfd, name, &st, 0);
	if (ret) {
		fprintf(stderr, "Error %d: %s while stating file %s. "
			"Skipping.\n",
			errno, strerror(errno), path);
		goto out;
	}

	dev = st.st_dev;
	if (one_file_system) {
		if (!one_fs_dev)
			one_fs_dev = dev;
		if (one_fs_dev != dev) {
			dprintf("Skipping file %s because of -x\n", path);
			goto out;
		}
	}

	if (S_ISDIR(st.st_mode)) {
		if (walk_dir(name))
			return 1;
		goto out;
	}

	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr, "Skipping non-regular file %s\n", path);
		goto out;
	}

	ret = faccessat(dirfd, name, R_OK, 0);
	if (ret) {
		fprintf(stderr, "Error %d: %s while accessing file %s. "
			"Skipping.\n",
			errno, strerror(errno), path);
		goto out;
	}

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		ret = errno;
		fprintf(stderr, "Error %d: %s while opening file \"%s\". "
			"Skipping.\n", ret, strerror(ret), path);
		goto out;
	}

	ret = check_file_btrfs(fd, &on_btrfs);
	if (ret) {
		close(fd);
		fprintf(stderr, "Skip file \"%s\" due to errors\n", path);
		goto out;
	}

	if (run_dedupe && !on_btrfs) {
		close(fd);
		fprintf(stderr, "\"%s\": Can only dedupe files on btrfs\n",
			path);
		return ENOSYS;
	}

	if (on_btrfs) {
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
				path);
			goto out;
		}
	} else {
		subvolid = st.st_dev;
	}

//	printf("\"%s\", ino: %llu, subvolid: %"PRIu64"\n", path,
//	       (unsigned long long)st.st_ino, subvolid);

	close(fd);

	walked_size += st.st_size;
	file = filerec_new(path, st.st_ino, subvolid);
	if (file == NULL) {
		fprintf(stderr, "Out of memory while allocating file record "
			"for: %s\n", path);
		return ENOMEM;
	}

out:
	pathp = pathtmp;
	return 0;
}

struct block {
	uint64_t	loff;
	unsigned int	flags;
	unsigned char	digest[DIGEST_LEN_MAX];
};

static void csum_whole_file(struct filerec *file, struct thread_params *params)
{
	struct hash_tree *tree = params->tree;
	uint64_t off = 0;
	ssize_t bytes = 0, bytes_read = 0;
	int ret = 0;
	struct fiemap_ctxt *fc = NULL;
	unsigned int flags, hole;

	int i;
	struct block *hashes = malloc(sizeof(struct block));
	int nb_hash = 0;
	int matched = 0;

	char *buf = malloc(blocksize);
	assert(buf != NULL);
	unsigned char *digest = malloc(DIGEST_LEN_MAX);
	assert(digest != NULL);
	static long long unsigned cur_num_filerecs = 0;

	GMutex *mutex = g_dataset_get_data(params, "mutex");

	__sync_add_and_fetch(&cur_num_filerecs, 1);
	printf("csum: %s \t[%llu/%llu] (%.2f%%)\n", file->filename,
	       cur_num_filerecs, num_filerecs,
		(double)cur_num_filerecs / (double)num_filerecs * 100);

	if (do_lookup_extents) {
		fc = alloc_fiemap_ctxt();
		if (fc == NULL) /* This should be non-fatal */
			fprintf(stderr,
				"Low memory allocating fiemap context for \"%s\"\n",
				file->filename);
	}

	ret = filerec_open(file, 0);
	if (ret)
		goto err_noclose;

	while (1) {
		bytes_read = read(file->fd, buf+bytes, blocksize-bytes);
		if (bytes_read < 0) {
			ret = errno;
			fprintf(stderr, "Unable to read file %s: %s\n",
				file->filename, strerror(ret));
			goto err;
		}

		/* Handle EOF */
		if (bytes_read == 0)
			break;

		bytes += bytes_read;

		/* Handle partial read */
		if (bytes_read > 0 && bytes < blocksize)
			continue;

		flags = hole = 0;
		if (fc) {
			unsigned int fieflags = 0;

			ret = fiemap_iter_get_flags(fc, file, off, &fieflags,
						    &hole);
			if (ret) {
				fprintf(stderr,
					"Fiemap error %d while scanning file "
					"\"%s\": %s\n", ret, file->filename,
					strerror(ret));

				free(fc);
				fc = NULL;
			} else {
				if (hole)
					flags |= FILE_BLOCK_HOLE;
				if (fieflags & FIEMAP_SKIP_FLAGS)
					flags |= FILE_BLOCK_SKIP_COMPARE;
				if (fieflags & FIEMAP_DEDUPED_FLAGS)
					flags |= FILE_BLOCK_DEDUPED;
			}
		}

		checksum_block(buf, bytes, digest);

		if (params->hfile == -1) {
			/* All-in-memory path */
			g_mutex_lock(mutex);
			ret = insert_hashed_block(tree, digest, file, off, flags);
			g_mutex_unlock(mutex);
			if (ret)
				break;
		} else {
			/* Swap-file path */
			hashes = realloc(hashes, sizeof(struct block) * (nb_hash + 1));
			hashes[nb_hash].loff = off;
			hashes[nb_hash].flags = flags;
			memcpy(hashes[nb_hash].digest, digest, DIGEST_LEN_MAX);
			nb_hash++;
		}

		off += bytes;
		bytes = 0;
	}

	if (params->hfile != -1) {
		/* swap-file path taken:
		 * write down all hashes, add all hashes to the bloom filter,
		 * and store possibly dups
		 */
		g_mutex_lock(mutex);
		file->num_blocks = nb_hash;
		ret = write_file_info(params->hfile, file);
		if (ret)
			goto err;

		for (i = 0; i < nb_hash; i++) {
			ret = bloom_add(&params->bloom,
				hashes[i].digest, DIGEST_LEN_MAX);
			if (ret == 1) {
				ret = insert_hashed_block(tree, hashes[i].digest,
						file, hashes[i].loff, hashes[i].flags);
				if (ret)
					goto err;
				params->bloom_match++;
				matched++;
			}

			ret = write_one_hash(params->hfile, hashes[i].loff,
					hashes[i].flags, hashes[i].digest);
			if (ret)
				goto err;
		}

		file->num_blocks = matched;

		params->num_files++;
		params->num_hashes += nb_hash;

		g_mutex_unlock(mutex);
	}

	filerec_close(file);
	free(digest);
	free(buf);
	if (fc)
		free(fc);

	return;

err:
	filerec_close(file);
	free(hashes);
err_noclose:
	free(digest);
	free(buf);
	if (fc)
		free(fc);

	fprintf(
		stderr,
		"Skipping file due to error %d (%s), %s\n",
		ret,
		strerror(ret),
		file->filename);

	g_mutex_lock(mutex);
	remove_hashed_blocks(tree, file);
	/*
	 * filerec_free will remove from the filerec tree keep it
	 * under tree_mutex until we have a need for real locking in
	 * filerec.c
	 */
	filerec_free(file);
	g_mutex_unlock(mutex);

	return;
}

int populate_hash_tree(struct hash_tree *tree, char* serialize_fname)
{
	int ret = 0;
	struct filerec *file, *tmp;
	GMutex mutex;
	GError *err = NULL;
	GThreadPool *pool;

	struct thread_params params = { tree, 0, 0, 0, };

	if (serialize_fname) {
		params.hfile = open(serialize_fname, O_WRONLY|O_CREAT|O_TRUNC, 0644);

		/* Write a dummy header */
		ret = write_header(params.hfile, 0, 0, blocksize);
		if (ret)
			goto out;

		ret = bloom_init(&params.bloom, walked_size / blocksize, 0.01);
		if (ret)
			goto out;
	} else {
		params.hfile = -1;
	}

	g_mutex_init(&mutex);
	g_dataset_set_data_full(&params, "mutex", &mutex,
				(GDestroyNotify) g_mutex_clear);

	pool = g_thread_pool_new((GFunc) csum_whole_file, &params, io_threads,
				 FALSE, &err);
	if (err != NULL) {
		fprintf(
			stderr,
			"Unable to create thread pool: %s\n",
			err->message);
		ret = -1;
		g_error_free(err);
		err = NULL;
		goto out;
	}

	printf("Using %u threads for file hashing phase\n", io_threads);

	list_for_each_entry_safe(file, tmp, &filerec_list, rec_list) {
		g_thread_pool_push(pool, file, &err);
		if (err != NULL) {
			fprintf(stderr,
					"g_thread_pool_push: %s\n",
					err->message);
			g_error_free(err);
			err = NULL;
		}
	}

	g_thread_pool_free(pool, FALSE, TRUE);

	if (serialize_fname) {
		/* Now, write the real header */
		ret = write_header(params.hfile, params.num_files,
				params.num_hashes, blocksize);
		if (ret)
			goto out;

		printf("Bloom gave us %i hashes as 'almost duplicate'\n",
			params.bloom_match);
	}

out:
	if (serialize_fname) {
		bloom_free(&params.bloom);
		close(params.hfile);
	}
	g_dataset_destroy(&params);

	return ret;
}
