/*
 * duperemove.c
 *
 * Copyright (C) 2013 SUSE.  All rights reserved.
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
#include <unistd.h>
#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <linux/limits.h>
#include <ctype.h>
#include <getopt.h>
#include <inttypes.h>
#include <assert.h>
#include <linux/fiemap.h>

#include <glib.h>

#include "rbtree.h"
#include "list.h"
#include "csum.h"
#include "filerec.h"
#include "hash-tree.h"
#include "results-tree.h"
#include "dedupe.h"
#include "util.h"
#include "serialize.h"
#include "btrfs-util.h"
#include "memstats.h"
#include "debug.h"

/* exported via debug.h */
int verbose = 0, debug = 0;

#define MIN_BLOCKSIZE	(4*1024)
/* max blocksize is somewhat arbitrary. */
#define MAX_BLOCKSIZE	(1024*1024)
#define DEFAULT_BLOCKSIZE	(128*1024)
static unsigned int blocksize = DEFAULT_BLOCKSIZE;

static char path[PATH_MAX] = { 0, };
char *pathp = path;
char *path_max = &path[PATH_MAX - 1];

static int run_dedupe = 0;
static int recurse_dirs = 0;
static int target_rw = 1;
static int version_only = 0;
static int one_file_system = 0;
static dev_t one_fs_dev = 0;

static int write_hashes = 0;
static int scramble_filenames = 0;
static int read_hashes = 0;
static char *serialize_fname = NULL;
static unsigned int hash_threads = 0;
static int do_lookup_extents = 1;

static int fancy_status = 0;

static void debug_print_block(struct file_block *e)
{
	struct filerec *f = e->b_file;

	printf("%s\tloff: %llu lblock: %llu seen: %u flags: 0x%x\n",
	       f->filename,
	       (unsigned long long)e->b_loff,
	       (unsigned long long)e->b_loff / blocksize, e->b_seen,
	       e->b_flags);
}

static void debug_print_tree(struct hash_tree *tree)
{
	struct rb_root *root = &tree->root;
	struct rb_node *node = rb_first(root);
	struct dupe_blocks_list *dups;
	struct file_block *block;
	struct list_head *p;

	if (!debug)
		return;

	dprintf("Block hash tree has %"PRIu64" hash nodes and %"PRIu64" block items\n",
		tree->num_hashes, tree->num_blocks);

	while (1) {
		if (node == NULL)
			break;

		dups = rb_entry(node, struct dupe_blocks_list, dl_node);

		dprintf("All blocks with hash: ");
		debug_print_digest(stdout, dups->dl_hash);
		dprintf("\n");

		list_for_each(p, &dups->dl_list) {
			block = list_entry(p, struct file_block, b_list);
			debug_print_block(block);
		}
		node = rb_next(node);
	}
}

static void print_dupes_table(struct results_tree *res)
{
	struct rb_root *root = &res->root;
	struct rb_node *node = rb_first(root);
	struct dupe_extents *dext;
	struct extent *extent;
	uint64_t calc_bytes = 0;

	printf("Simple read and compare of file data found %u instances of "
	       "extents that might benefit from deduplication.\n",
	       res->num_dupes);

	if (res->num_dupes == 0)
		return;

	while (1) {
		uint64_t len, len_blocks;

		if (node == NULL)
			break;

		dext = rb_entry(node, struct dupe_extents, de_node);

		len = dext->de_len;
		len_blocks = len / blocksize;
		calc_bytes += dext->de_score;

		vprintf("%u extents had length %llu Blocks (%llu) for a"
			" score of %llu.\n", dext->de_num_dupes,
			(unsigned long long)len_blocks,
			(unsigned long long)len,
			(unsigned long long)dext->de_score);
		if (debug) {
			printf("Hash is: ");
			debug_print_digest(stdout, dext->de_hash);
			printf("\n");
		}

		printf("Start\t\tLength\t\tFilename (%u extents)\n",
		       dext->de_num_dupes);
		list_for_each_entry(extent, &dext->de_extents, e_list) {
			printf("%s\t%s\t\"%s\"\n",
			       pretty_size(extent->e_loff),
			       pretty_size(len),
			       extent->e_file->filename);
		}

		node = rb_next(node);
	}
}

static void process_dedupe_results(struct dedupe_ctxt *ctxt,
				   uint64_t *kern_bytes)
{
	int done = 0;
	int target_status;
	uint64_t target_loff, target_bytes;
	struct filerec *f;

	while (!done) {
		done = pop_one_dedupe_result(ctxt, &target_status, &target_loff,
					     &target_bytes, &f);
		*kern_bytes += target_bytes;

		dprintf("\"%s\":\toffset: %llu\tprocessed bytes: %llu"
			"\tstatus: %d\n", f->filename,
			(unsigned long long)target_loff,
			(unsigned long long)target_bytes, target_status);
	}
}

static void add_shared_extents(struct dupe_extents *dext, uint64_t *shared)
{
	int ret = 0;
	struct extent *extent;
	struct filerec *file;

	list_for_each_entry(extent, &dext->de_extents, e_list) {
		file = extent->e_file;

		if (filerec_open(file, 0))
			continue;

		ret = filerec_count_shared(file, extent->e_loff, dext->de_len,
					   shared);
		if (ret) {
			fprintf(stderr, "%s: fiemap error %d: %s\n",
				extent->e_file->filename, ret, strerror(ret));
		}
		filerec_close(file);
	}
}

static int dedupe_extent_list(struct dupe_extents *dext, uint64_t *fiemap_bytes,
			      uint64_t *kern_bytes)
{
	int ret = 0;
	int last = 0;
	int rc;
	uint64_t shared_prev, shared_post;
	struct extent *extent;
	struct dedupe_ctxt *ctxt = NULL;
	uint64_t len = dext->de_len;
	LIST_HEAD(open_files);
	struct filerec *file;
	struct extent *prev = NULL;
	struct extent *to_add;

	abort_on(dext->de_num_dupes < 2);

	shared_prev = shared_post = 0ULL;
	add_shared_extents(dext, &shared_prev);

	list_for_each_entry(extent, &dext->de_extents, e_list) {
		vprintf("%s\tstart block: %llu (%llu)\n",
			extent->e_file->filename,
			(unsigned long long)extent->e_loff / blocksize,
			(unsigned long long)extent->e_loff);

		if (list_is_last(&extent->e_list, &dext->de_extents))
			last = 1;

		to_add = extent;
		file = extent->e_file;
		ret = filerec_open_once(file, target_rw, &open_files);
		if (ret) {
			fprintf(stderr, "%s: Skipping dedupe.\n",
				extent->e_file->filename);
			/*
			 * If this was our last duplicate extent in
			 * the list, and we added dupes from a
			 * previous iteration of the loop we need to
			 * run dedupe before exiting.
			 */
			if (ctxt && last)
				goto run_dedupe;
			continue;
		}

		if (ctxt == NULL) {
			ctxt = new_dedupe_ctxt(dext->de_num_dupes,
					       extent->e_loff, len,
					       extent->e_file);
			if (ctxt == NULL) {
				fprintf(stderr, "Out of memory while "
					"allocating dedupe context.\n");
				ret = ENOMEM;
				goto out;
			}

			if (!last) {
				/*
				 * We added our file already here via
				 * new_dedupe_ctxt, so go to the next
				 * loop iteration.
				 */
				continue;
			}

			/*
			 * We started a new context, but only have one
			 * extent left to dedupe (need at least
			 * 2). This is pretty rare but instead of
			 * leaving it not-deduped, we can pick the
			 * most recent extent off the list and re-add
			 * that. The old extent won't be deduped again
			 * but this one will.
			 */
			abort_on(!prev);
			to_add = prev; /* The ole' extent switcharoo */
		}
		prev = extent; /* save previous extent for condition above */

		rc = add_extent_to_dedupe(ctxt, to_add->e_loff, to_add->e_file);
		if (rc) {
			if (rc < 0) {
				/* This can only be ENOMEM. */
				fprintf(stderr, "%s: Request not queued.\n",
					to_add->e_file->filename);
				ret = ENOMEM;
				goto out;
			}

			if (last)
				goto run_dedupe;
			continue;
		}

run_dedupe:

		/*
		 * We can get here with only the target extent (0 queued) if
		 * filerec_open_list fails on the 2nd (and last)
		 * extent.
		 */
		if (ctxt->num_queued) {
			printf("Dedupe %d extents with target: (%s, %s), "
			       "\"%s\"\n",
			       ctxt->num_queued,
			       pretty_size(ctxt->orig_file_off),
			       pretty_size(ctxt->orig_len),
			       ctxt->ioctl_file->filename);

			ret = dedupe_extents(ctxt);
			if (ret) {
				ret = errno;
				fprintf(stderr,
					"FAILURE: Dedupe ioctl returns %d: %s\n",
					ret, strerror(ret));
			}

			process_dedupe_results(ctxt, kern_bytes);
		}

		filerec_close_files_list(&open_files);
		free_dedupe_ctxt(ctxt);
		ctxt = NULL;
	}

	abort_on(ctxt != NULL);
	abort_on(!list_empty(&open_files));

	add_shared_extents(dext, &shared_post);
	/*
	 * It's entirely possible that some other process is
	 * manipulating files underneath us. Take care not to
	 * report some randomly enormous 64 bit value.
	 */
	if (shared_prev  < shared_post)
		*fiemap_bytes += shared_post - shared_prev;

	/* The only error we want to bubble up is ENOMEM */
	ret = 0;
out:
	/*
	 * ENOMEM error during context allocation may have caused open
	 * files to stay in our list.
	 */
	filerec_close_files_list(&open_files);
	/*
	 * We might have allocated a context above but not
	 * filled it with any extents, make sure to free it
	 * here.
	 */
	free_dedupe_ctxt(ctxt);

	abort_on(!list_empty(&open_files));

	return ret;
}

static void dedupe_results(struct results_tree *res)
{
	int ret;
	struct rb_root *root = &res->root;
	struct rb_node *node = rb_first(root);
	struct dupe_extents *dext;
	uint64_t fiemap_bytes = 0;
	uint64_t kern_bytes = 0;

	print_dupes_table(res);

	if (RB_EMPTY_ROOT(root)) {
		printf("Nothing to dedupe.\n");
		return;
	}

	while (node) {
		dext = rb_entry(node, struct dupe_extents, de_node);

		ret = dedupe_extent_list(dext, &fiemap_bytes, &kern_bytes);
		if (ret)
			break;

		node = rb_next(node);
	}

	printf("Kernel processed data (excludes target files): %s\nComparison "
	       "of extent info shows a net change in shared extents of: %s\n",
	       pretty_size(kern_bytes), pretty_size(fiemap_bytes));
}

static void csum_whole_file(struct filerec *file, struct hash_tree *tree)
{
	uint64_t off = 0;
	ssize_t bytes = 0, bytes_read = 0;
	int ret = 0;
	struct fiemap_ctxt *fc = NULL;
	unsigned int flags, hole;

	char *buf = malloc(blocksize);
	assert(buf != NULL);
	unsigned char *digest = malloc(DIGEST_LEN_MAX);
	assert(digest != NULL);
	static long long unsigned cur_num_filerecs = 0;

	GMutex *tree_mutex = g_dataset_get_data(tree, "mutex");

	printf("csum: %s \t[%llu/%llu]\n", file->filename,
	       __sync_add_and_fetch(&cur_num_filerecs, 1), num_filerecs);

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

		/* Is this necessary? */
		memset(digest, 0, DIGEST_LEN_MAX);

		checksum_block(buf, bytes, digest);

		g_mutex_lock(tree_mutex);
		ret = insert_hashed_block(tree, digest, file, off, flags);
		g_mutex_unlock(tree_mutex);
		if (ret)
			break;

		off += bytes;
		bytes = 0;
	}

	filerec_close(file);
	free(digest);
	free(buf);
	if (fc)
		free(fc);

	return;

err:
	filerec_close(file);
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

	g_mutex_lock(tree_mutex);
	remove_hashed_blocks(tree, file);
	/*
	 * filerec_free will remove from the filerec tree keep it
	 * under tree_mutex until we have a need for real locking in
	 * filerec.c
	 */
	filerec_free(file);
	g_mutex_unlock(tree_mutex);

	return;
}

static int populate_hash_tree(struct hash_tree *tree)
{
	int ret = 0;
	struct filerec *file, *tmp;
	GMutex tree_mutex;
	GError *err = NULL;
	GThreadPool *pool;

	g_mutex_init(&tree_mutex);
	g_dataset_set_data_full(tree, "mutex", &tree_mutex,
				(GDestroyNotify) g_mutex_clear);

	if (!hash_threads)
		hash_threads = g_get_num_processors();

	pool = g_thread_pool_new((GFunc) csum_whole_file, tree, hash_threads,
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

	printf("Using %d threads for file hashing phase\n", hash_threads);

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
out:
	g_dataset_remove_data(tree, "mutex");

	return ret;
}

static void usage(const char *prog)
{
	printf("duperemove %s\n", VERSTRING);
	if (version_only)
		return;

	printf("Find duplicate extents and print them to stdout\n\n");
	printf("Usage: %s [-r] [-d] [-A] [-b blocksize] [-v] [--debug]"
	       " OBJECTS\n", prog);
	printf("Where \"OBJECTS\" is a list of files (or directories) which\n");
	printf("we want to find duplicate extents in. If a directory is \n");
	printf("specified, all regular files inside of it will be scanned.\n");
	printf("\n\t<switches>\n");
	printf("\t-r\t\tEnable recursive dir traversal.\n");
	printf("\t-d\t\tDe-dupe the results - only works on btrfs.\n");
	printf("\t-A\t\tOpens files readonly when deduping. Primarily for use by privileged users on readonly snapshots\n");
	printf("\t-b bsize\tUse bsize blocks. Default is %dk.\n",
	       DEFAULT_BLOCKSIZE / 1024);
	printf("\t-h\t\tPrint numbers in human-readable format.\n");
	printf("\t-x\t\tDon't cross filesystem boundaries.\n");
	printf("\t-v\t\tBe verbose.\n");
	printf("\t--hash-threads=N\n\t\t\tUse N threads for hashing phase. "
	       "Default is automatically detected.\n");
	printf("\t--read-hashes=hashfile\n\t\t\tRead hashes from a hashfile. "
	       "A file list is not required with this option.\n");
	printf("\t--write-hashes=hashfile\n\t\t\tWrite hashes to a hashfile. "
	       "These can be read in at a later date and deduped from.\n");
	printf("\t--lookup-extents=[yes|no]\n\t\t\tLookup extent info during "
	       "checksum phase. Defaults to yes.\n");
	printf("\t--debug\t\tPrint debug messages, forces -v if selected.\n");
	printf("\t--help\t\tPrints this help text.\n");
}

static int add_file(const char *name, int dirfd);

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
static int add_file(const char *name, int dirfd)
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

static int parse_yesno_option(char *arg, int default_val)
{
	if (strncmp(arg, "yes", 3) == 0)
		return 1;
	else if (strncmp(arg, "no", 2) == 0)
		return 0;
	return default_val;
}

enum {
	DEBUG_OPTION = CHAR_MAX + 1,
	HELP_OPTION,
	VERSION_OPTION,
	WRITE_HASHES_OPTION,
	WRITE_HASHES_SCRAMBLE_OPTION,
	READ_HASHES_OPTION,
	HASH_THREADS_OPTION,
	LOOKUP_EXTENTS_OPTION,
	ONE_FILESYSTEM_OPTION,
};

/*
 * Ok this is doing more than just parsing options.
 */
static int parse_options(int argc, char **argv)
{
	int i, c, numfiles;
	static struct option long_ops[] = {
		{ "debug", 0, 0, DEBUG_OPTION },
		{ "help", 0, 0, HELP_OPTION },
		{ "version", 0, 0, VERSION_OPTION },
		{ "write-hashes", 1, 0, WRITE_HASHES_OPTION },
		{ "write-hashes-scramble", 1, 0, WRITE_HASHES_SCRAMBLE_OPTION },
		{ "read-hashes", 1, 0, READ_HASHES_OPTION },
		{ "hash-threads", 1, 0, HASH_THREADS_OPTION },
		{ "lookup-extents", 1, 0, LOOKUP_EXTENTS_OPTION },
		{ "one-file-system", 0, 0, ONE_FILESYSTEM_OPTION },
		{ 0, 0, 0, 0}
	};

	if (argc < 2)
		return 1;

	while ((c = getopt_long(argc, argv, "Ab:vdDrh?x", long_ops, NULL))
	       != -1) {
		switch (c) {
		case 'A':
			target_rw = 0;
			break;
		case 'b':
			blocksize = parse_size(optarg);
			if (blocksize < MIN_BLOCKSIZE ||
			    blocksize > MAX_BLOCKSIZE)
				return EINVAL;
			break;
		case 'd':
		case 'D':
			run_dedupe = 1;
			break;
		case 'r':
			recurse_dirs = 1;
			break;
		case VERSION_OPTION:
			version_only = 1;
			break;
		case DEBUG_OPTION:
			debug = 1;
			/* Fall through */
		case 'v':
			verbose = 1;
			break;
		case 'h':
			human_readable = 1;
			break;
		case WRITE_HASHES_SCRAMBLE_OPTION:
			scramble_filenames = 1;
		case WRITE_HASHES_OPTION:
			write_hashes = 1;
			serialize_fname = strdup(optarg);
			break;
		case READ_HASHES_OPTION:
			read_hashes = 1;
			serialize_fname = strdup(optarg);
			break;
		case HASH_THREADS_OPTION:
			hash_threads = strtoul(optarg, NULL, 10);
			if (!hash_threads)
				return EINVAL;
			break;
		case LOOKUP_EXTENTS_OPTION:
			do_lookup_extents = parse_yesno_option(optarg, 1);
			break;
		case ONE_FILESYSTEM_OPTION:
		case 'x':
			one_file_system = 1;
			break;
		case HELP_OPTION:
		case '?':
		default:
			version_only = 0;
			return 1;
		}
	}

	numfiles = argc - optind;

	/* Filter out option combinations that don't make sense. */
	if (write_hashes &&
	    (read_hashes || run_dedupe)) {
		if (run_dedupe)
			fprintf(stderr,
				"Error: Can not dedupe with --write-hashes "
				"option. Try writing hashes and then deduping "
				"with --read-hashes instead.\n");
		if (read_hashes)
			fprintf(stderr,
				"Error: Specify only one of --write-hashes or "
				"--read-hashes.\n");

		return 1;
	}

	if (read_hashes) {
		if (numfiles) {
			fprintf(stderr,
				"Error: --read-hashes option does not take a "
				"file list argument\n");
			return 1;
		}
		goto out_nofiles;
	}

	for (i = 0; i < numfiles; i++) {
		const char *name = argv[i + optind];

		if (add_file(name, AT_FDCWD))
			return 1;
	}

	/* This can happen if for example, all files passed in on
	 * command line are bad. */
	if (list_empty(&filerec_list))
		return EINVAL;

out_nofiles:

	return 0;
}

static void record_match(struct results_tree *res, unsigned char *digest,
			 struct filerec *orig, struct filerec *walk,
			 struct file_block **start, struct file_block **end)
{
	int ret;
	uint64_t soff[2], eoff[2];
	struct filerec *recs[2];
	uint64_t len;

	abort_on(start[0]->b_file != orig);
	abort_on(start[1]->b_file != walk);

	recs[0] = start[0]->b_file;
	recs[1] = start[1]->b_file;

	soff[0] = start[0]->b_loff;
	soff[1] = start[1]->b_loff;

	eoff[0] = blocksize + end[0]->b_loff;
	eoff[1] = blocksize + end[1]->b_loff;

	len = eoff[0] - soff[0];

	ret = insert_result(res, digest, recs, soff, eoff);
	if (ret) {
		abort_on(ret != ENOMEM); /* Only error possible here. */
		fprintf(stderr, "Out of memory while processing results\n");
		print_mem_stats();
		exit(ENOMEM);
	}

	dprintf("Duplicated extent of %llu blocks in files:\n%s\t\t%s\n",
		(unsigned long long)len / blocksize, orig->filename,
		walk->filename);

	dprintf("%llu-%llu\t\t%llu-%llu\n",
		(unsigned long long)soff[0] / blocksize,
		(unsigned long long)eoff[0] / blocksize,
		(unsigned long long)soff[1] / blocksize,
		(unsigned long long)eoff[1] / blocksize);
}

static int walk_dupe_block(struct filerec *orig_file,
			   struct file_block *orig_file_block,
			   struct filerec *walk_file,
			   struct file_block *walk_file_block,
			   struct results_tree *res)
{
	struct file_block *orig = orig_file_block;
	struct file_block *block = walk_file_block;
	struct file_block *start[2] = { orig, block };
	struct file_block *end[2];
	struct running_checksum *csum;
	unsigned char match_id[DIGEST_LEN_MAX] = {0, };

	if (block_seen(block) || block_seen(orig))
		goto out;

	csum = start_running_checksum();

	abort_on(block->b_parent != orig->b_parent);

	while (block->b_parent == orig->b_parent) {
		mark_block_seen(block);
		mark_block_seen(orig);

		end[0] = orig;
		end[1] = block;

		add_to_running_checksum(csum, digest_len,
					block->b_parent->dl_hash);

		/*
		 * This is kind of ugly, however it does correctly
		 * signify the end of our list.
		 */
		if (orig->b_file_next.next == &orig_file->block_list ||
		    block->b_file_next.next == &walk_file->block_list)
			break;

		orig =	list_entry(orig->b_file_next.next, struct file_block,
				   b_file_next);
		block =	list_entry(block->b_file_next.next, struct file_block,
				   b_file_next);
	}

	finish_running_checksum(csum, match_id);

	record_match(res, match_id, orig_file, walk_file,
		     start, end);
out:
	return 0;
}

/*
 * Start an extent search (with orig_block) at each block in our dups
 * list which is owned by walk_file.
 */
static void lookup_walk_file_hash_head(struct file_block *orig_block,
				       struct filerec *walk_file,
				       struct results_tree *res)
{
	struct dupe_blocks_list *parent = orig_block->b_parent;
	struct file_block *cur;
	struct file_hash_head *head = find_file_hash_head(parent, walk_file);

	/* find_file_dups should have checked this for us already */
	abort_on(head == NULL);

	list_for_each_entry(cur, &head->h_blocks, b_head_list) {
		/* Ignore self. Technically this shouldn't happen (see above)
		 * until we allow walking a file against itself. */
		if (cur == orig_block)
			continue;

		abort_on(cur->b_file != walk_file);

		if (walk_dupe_block(orig_block->b_file, orig_block,
				    walk_file, cur, res))
			break;
	}
}

static void find_file_dupes(struct filerec *file, struct filerec *walk_file,
			    struct results_tree *res)
{
	struct file_block *cur;

	list_for_each_entry(cur, &file->block_list, b_file_next) {
		if (block_seen(cur))
			continue;

		if (!file_in_dups_list(cur->b_parent, walk_file))
			continue;

		/*
		 * For each file block with the same hash:
		 *  - Traverse, along with original file until we have no match
		 *     - record
		 */
		lookup_walk_file_hash_head(cur, walk_file, res);
	}
	clear_all_seen_blocks();
}

static int compare_files(struct results_tree *res, struct filerec *file1, struct filerec *file2)
{
	dprintf("comparing %s and %s\n", file1->filename, file2->filename);
	find_file_dupes(file1, file2, res);

	return mark_filerecs_compared(file1, file2);
}

static int walk_dupe_hashes(struct dupe_blocks_list *dups,
			    struct results_tree *res)
{
	int ret;
	struct file_block *block1, *block2;
	struct filerec *file1, *file2;

#define SKIP_FLAGS	(FILE_BLOCK_SKIP_COMPARE|FILE_BLOCK_HOLE)

	list_for_each_entry(block1, &dups->dl_list, b_list) {
		if (block1->b_flags & SKIP_FLAGS)
			continue;

		file1 = block1->b_file;
		block2 = block1;
		list_for_each_entry_continue(block2,
					     &dups->dl_list,
					     b_list) {
			if (block2->b_flags & SKIP_FLAGS)
				continue;

			/*
			 * Don't compare if both blocks are already
			 * marked as shared. In thoery however the
			 * blocks might not be shared with each other
			 * so we will want to account for this in a
			 * future change.
			 */
			if (block1->b_flags & FILE_BLOCK_DEDUPED
			    && block2->b_flags & FILE_BLOCK_DEDUPED)
				continue;

			file2 = block2->b_file;

			if (block_ever_seen(block2))
				continue;

			if (filerecs_compared(file1, file2))
				continue;

			if (file1 != file2) {
				ret = compare_files(res, file1, file2);
				if (ret)
					return ret;
				/*
				 * End here, after finding a set of
				 * duplicates. Future runs will see
				 * the deduped blocks and skip them,
				 * allowing us to dedupe any remaining
				 * extents (if any)
				 */
				break;
			}
		}
	}
	return 0;
}

static void update_extent_search_status(struct hash_tree *tree,
					unsigned long long processed)
{
	static int last_pos = -1;
	int i, pos;
	int width = 40;
	float progress;

	if (!fancy_status)
		return;

	progress = (float) processed / tree->num_blocks;
	pos = width * progress;

	/* Only update our status every width% */
	if (pos <= last_pos)
		return;
	last_pos = pos;

	printf("\r[");
	for(i = 0; i < width; i++) {
		if (i < pos)
			printf("#");
		else if (i == pos)
			printf("%%");
		else
			printf(" ");
	}
	printf("]");
	fflush(stdout);
}

static void clear_extent_search_status(unsigned long long processed,
				       int err)
{
	if (!fancy_status)
		return;

	if (err)
		printf("\nSearch exited (%llu processed) with error %d: "
		       "\"%s\"\n", processed, err, strerror(err));
	else
		printf("\nSearch completed with no errors.             \n");
	fflush(stdout);
}

static int find_all_dups(struct hash_tree *tree, struct results_tree *res)
{
	int ret = 0;
	struct rb_root *root = &tree->root;
	struct rb_node *node = rb_first(root);
	struct dupe_blocks_list *dups;
	unsigned long long processed = 0;

	while (1) {
		if (node == NULL)
			break;

		dups = rb_entry(node, struct dupe_blocks_list, dl_node);

		update_extent_search_status(tree, processed);

		if (dups->dl_num_elem > 1) {
			ret = walk_dupe_hashes(dups, res);
			if (ret)
				goto out;
		}

		processed += dups->dl_num_elem;

		node = rb_next(node);
	}

	update_extent_search_status(tree, processed);
out:

	clear_extent_search_status(processed, ret);
	return ret;
}

int main(int argc, char **argv)
{
	int ret;
	struct hash_tree tree;
	struct results_tree res;
	struct filerec *file;

	if (init_hash())
		return ENOMEM;

	init_filerec();
	init_hash_tree(&tree);
	init_results_tree(&res);

	if (parse_options(argc, argv)) {
		usage(argv[0]);
		return EINVAL;
	}

	if (isatty(STDOUT_FILENO))
		fancy_status = 1;

	if (read_hashes) {
		ret = read_hash_tree(serialize_fname, &tree, &blocksize, NULL);
		if (ret == FILE_VERSION_ERROR) {
			fprintf(stderr,
				"Hash file \"%s\": "
				"Version mismatch (mine: %d.%d).\n",
				serialize_fname, HASH_FILE_MAJOR,
				HASH_FILE_MINOR);
			goto out;
		} else if (ret == FILE_MAGIC_ERROR) {
			fprintf(stderr,
				"Hash file \"%s\": "
				"Bad magic.\n",
				serialize_fname);
			goto out;
		} else if (ret) {
			fprintf(stderr, "Hash file \"%s\": "
				"Error %d while reading: %s.\n",
				serialize_fname, ret, strerror(ret));
			goto out;
		}
	}

	printf("Using %uK blocks\n", blocksize/1024);

	if (!read_hashes) {
		ret = populate_hash_tree(&tree);
		if (ret) {
			fprintf(stderr, "Error while populating extent tree!\n");
			goto out;
		}
	}

	debug_print_tree(&tree);

	if (write_hashes) {
		ret = serialize_hash_tree(serialize_fname, &tree, blocksize,
					  scramble_filenames);
		if (ret)
			fprintf(stderr, "Error %d while writing to hash file\n", ret);
		goto out;
	} else {
		printf("Hashed %"PRIu64" blocks, resulting in %"PRIu64" unique "
		       "hashes. Calculating duplicate extents - this may take "
		       "some time.\n", tree.num_blocks, tree.num_hashes);
	}

	ret = find_all_dups(&tree, &res);
	if (ret) {
		fprintf(stderr, "Error %d while finding duplicate extents: %s\n",
			ret, strerror(ret));
		goto out;
	}

	if (debug) {
		print_dupes_table(&res);
		printf("\n\nRemoving overlapping extents\n\n");
	}

	list_for_each_entry(file, &filerec_list, rec_list) {
		remove_overlapping_extents(&res, file);
	}

	if (run_dedupe)
		dedupe_results(&res);
	else
		print_dupes_table(&res);

out:
	if (ret == ENOMEM || debug)
		print_mem_stats();

	return ret;
}
