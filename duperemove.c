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
 */

#include <sys/types.h>
#include <sys/stat.h>
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

#include "rbtree.h"
#include "list.h"
#include "csum.h"
#include "filerec.h"
#include "hash-tree.h"
#include "results-tree.h"
#include "dedupe.h"

static int verbose = 0, debug = 0;
#define dprintf(args...)	if (debug) printf(args)
#define vprintf(args...)	if (verbose) printf(args)
#define abort_on(condition) do {					\
		if (condition) {					\
			printf("ERROR: %s:%d\n", __FILE__, __LINE__);\
			abort();					\
		}							\
	} while(0)

#define MIN_BLOCKSIZE	(4*1024)
/* max blocksize is somewhat arbitrary. */
#define MAX_BLOCKSIZE	(1024*1024)
#define DEFAULT_BLOCKSIZE	(128*1024)
static unsigned int blocksize = DEFAULT_BLOCKSIZE;
static char *buf = NULL;

static unsigned char digest[DIGEST_LEN_MAX] = { 0, };
static char path[PATH_MAX] = { 0, };
char *pathp = path;
char *path_max = &path[PATH_MAX - 1];

static int run_dedupe = 0;
static int recurse_dirs = 0;

#define MAX_DEDUPES_PER_IOCTL	128

static void debug_print_block(struct file_block *e)
{
	struct filerec *f = e->b_file;

	printf("%s\tloff: %llu lblock: %llu\n", f->filename,
	       (unsigned long long)e->b_loff,
	       (unsigned long long)e->b_loff / blocksize);
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

	dprintf("Block hash tree has %u hash nodes and %u block items\n",
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

static void print_results(struct results_tree *res)
{
	struct rb_root *root = &res->root;
	struct rb_node *node = rb_first(root);
	struct dupe_extents *dext;
	struct extent *extent;

	printf("Found %u instances of duplicated extents\n", res->num_dupes);

	while (1) {
		uint64_t len, len_blocks;

		if (node == NULL)
			break;

		dext = rb_entry(node, struct dupe_extents, de_node);

		len = dext->de_len;
		len_blocks = len / blocksize;

		printf("(dext: 0x%p) %u extents had length %llu (%llu) for a score of %llu.\n", (void *)dext,
		       dext->de_num_dupes, (unsigned long long)len_blocks,
		       (unsigned long long)len,
		       (unsigned long long)dext->de_score);
		if (verbose) {
			printf("Hash is: ");
			debug_print_digest(stdout, dext->de_hash);
			printf("\n");
		}
		list_for_each_entry(extent, &dext->de_extents, e_list) {
			printf("%s\tstart block: %llu (%llu)\n",
			       extent->e_file->filename,
			       (unsigned long long)extent->e_loff / blocksize,
			       (unsigned long long)extent->e_loff);
		}

		node = rb_next(node);
	}
}

static int run_dedupe_and_close_files(struct dedupe_ctxt **ret_ctxt)
{
	int ret, i;
	struct dedupe_ctxt *ctxt = *ret_ctxt;

	printf("Running dedupe.\n");

	ret = dedupe_extents(ctxt);
	if (ret) {
		ret = errno;
		fprintf(stderr,
			"FAILURE: Dedupe ioctl returns %d: %s\n",
			ret, strerror(ret));
		goto cleanup;
	}

	printf("Dedupe from: \"%s\"\toffset: %llu\tlen: %llu\n",
	       ctxt->ioctl_file->filename,
	       (unsigned long long)ctxt->ioctl_file_off,
	       (unsigned long long)ctxt->len);

	for (i = 0; i < num_dedupe_requests(ctxt); i++) {
		uint64_t target_loff, target_bytes;
		int status;
		struct filerec *f;

		get_dedupe_result(ctxt, i, &status, &target_loff,
				  &target_bytes, &f);

		printf("\"%s\":\toffset: %llu\tdeduped bytes: %llu"
		       "\tstatus: %d\n", f->filename,
		       (unsigned long long)target_loff,
		       (unsigned long long)target_bytes, status);

		filerec_close(f);
	}

cleanup:
	free_dedupe_ctxt(ctxt);
	*ret_ctxt = NULL;

	return ret;
}

static void dedupe_results(struct results_tree *res)
{
	int ret, dupes_added;
	struct rb_root *root = &res->root;
	struct rb_node *node = rb_first(root);
	struct dupe_extents *dext;
	struct extent *extent;
	struct dedupe_ctxt *ctxt = NULL;

	printf("Found %u instances of duplicated extents\n", res->num_dupes);

	while (1) {
		uint64_t len, len_blocks;

		if (node == NULL)
			break;

		dext = rb_entry(node, struct dupe_extents, de_node);

		len = dext->de_len;
		len_blocks = len / blocksize;
		dupes_added = 0;

		vprintf("%u extents had length %llu (%llu) for a score of %llu.\n",
			dext->de_num_dupes, (unsigned long long)len_blocks,
			(unsigned long long)len,
			(unsigned long long)dext->de_score);
		if (verbose) {
			printf("Hash is: ");
			debug_print_digest(stdout, dext->de_hash);
			printf("\n");
		}
		list_for_each_entry(extent, &dext->de_extents, e_list) {
			vprintf("%s\tstart block: %llu (%llu)\n",
				extent->e_file->filename,
				(unsigned long long)extent->e_loff / blocksize,
				(unsigned long long)extent->e_loff);

			ret = filerec_open(extent->e_file);
			if (ret) {
				fprintf(stderr, "%s: Skipping dedupe.\n",
					extent->e_file->filename);
				continue;
			}

			if (ctxt == NULL) {
				ctxt = new_dedupe_ctxt(dext->de_num_dupes,
						       extent->e_loff, len,
						       extent->e_file);
				if (ctxt == NULL) {
					fprintf(stderr, "Out of memory while "
						"allocating dedupe context.\n");
					return;
				}
			} else {
				add_extent_to_dedupe(ctxt, extent->e_loff, len,
						     extent->e_file);
				dupes_added++;
			}

			if (dupes_added > MAX_DEDUPES_PER_IOCTL) {
				ret = run_dedupe_and_close_files(&ctxt);
				if (ret) {
					fprintf(stderr,
						"FAILURE: Dedupe ioctl returns %d: %s\n",
						ret, strerror(ret));
				}

				dupes_added = 0;
			}
		}

		if (dupes_added) {
			ret = run_dedupe_and_close_files(&ctxt);
			if (ret) {
				fprintf(stderr,
					"FAILURE: Dedupe ioctl returns %d: %s\n",
					ret, strerror(ret));
			}
		}

		/*
		 * We might have allocated a context above but not
		 * filled it with any extents, make sure to free it
		 * here.
		 */
		free_dedupe_ctxt(ctxt);
		ctxt = NULL;

		node = rb_next(node);
	}
}

static int csum_whole_file(struct hash_tree *tree, struct filerec *file)
{
	int ret, expecting_eof = 0;
	ssize_t bytes;
	uint64_t off;

	vprintf("csum: %s\n", file->filename);

	ret = filerec_open(file);
	if (ret)
		return ret;

	ret = off = 0;

	while (1) {
		bytes = read(file->fd, buf, blocksize);
		if (bytes < 0) {
			ret = errno;
			fprintf(stderr, "Unable to read file %s: %s\n",
				file->filename, strerror(ret));
			break;
		}

		if (bytes == 0)
			break;

		/*
		 * TODO: This should be a graceful exit or we replace
		 * the read call above with a wrapper which retries
		 * until an eof.
		 */
		abort_on(expecting_eof);

		if (bytes < blocksize) {
			expecting_eof = 1;
			continue;
		}

		/* Is this necessary? */
		memset(digest, 0, DIGEST_LEN_MAX);

		checksum_block(buf, bytes, digest);

		ret = insert_hashed_block(tree, digest, file, off);
		if (ret)
			break;

		off += bytes;
	}

	filerec_close(file);

	return ret;
}

static int populate_hash_tree(struct hash_tree *tree)
{
	int ret = -1;
	struct filerec *file, *tmp;

	list_for_each_entry_safe(file, tmp, &filerec_list, rec_list) {
		ret = csum_whole_file(tree, file);
		if (ret) {
			fprintf(stderr, "Skipping file due to error %d (%s), "
				"%s\n", ret, strerror(ret), file->filename);
			remove_hashed_blocks(tree, file);
			filerec_free(file);
		}
	}

	return ret;
}

static void usage(const char *prog)
{
	printf("duperemove %s\n", VERSTRING);
	printf("Find duplicate extents and print them to stdout\n\n");
	printf("Usage: %s [-v] [-d] [-h] [-b blocksize-in-K] OBJECTS\n", prog);
	printf("Where \"OBJECTS\" is a list of files (or directories) which\n");
	printf("we want to find duplicate extents in. If a directory is \n");
	printf("specified, all regular files inside of it will be scanned.\n");
	printf("\n\t<switches>\n");
	printf("\t-b bsize\tUse bsize blocks - specify in kilobytes. Default is %d.\n", DEFAULT_BLOCKSIZE / 1024);
	printf("\t-r\t\tEnable recursive dir traversal.\n");
	printf("\t-D\t\tDe-dupe the results - only works on btrfs.\n");
	printf("\t-v\t\tBe verbose.\n");
	printf("\t-d\t\tPrint debug messages, forces -v if selected.\n");
	printf("\t-h\t\tPrints this help text.\n");
}

static void add_file(const char *name, int dirfd);

static void walk_dir(const char *name)
{
	struct dirent *entry;
	DIR *dirp;

	if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
		return;

	dirp = opendir(path);
	if (dirp == NULL) {
		fprintf(stderr, "Error %d: %s while opening directory %s\n",
			errno, strerror(errno), name);
		return;
	}

	do {
		errno = 0;
		entry = readdir(dirp);
		if (entry) {
			if (entry->d_type == DT_REG ||
			    (recurse_dirs && entry->d_type == DT_DIR))
				add_file(entry->d_name, dirfd(dirp));
		}
	} while (entry != NULL);

	if (errno) {
		fprintf(stderr, "Error %d: %s while reading directory %s\n",
			errno, strerror(errno), path);
	}

	closedir(dirp);
}

static void add_file(const char *name, int dirfd)
{
	int ret, len = strlen(name);
	struct stat st;
	char *pathtmp;

	/* We can get this from walk_dir */
	if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
		return;

	if (len > (path_max - pathp)) {
		fprintf(stderr, "Path max exceeded: %s %s\n", path, name);
		return;
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

	if (S_ISDIR(st.st_mode)) {
		walk_dir(name);
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

	if (filerec_new(path) == NULL) {
		fprintf(stderr, "Out of memory while allocating file record "
			"for: %s\n", path);
		exit(ENOMEM);
	}

	dprintf("added file: %s\n", path);

out:
	pathp = pathtmp;
}

/*
 * Ok this is doing more than just parsing options.
 */
static int parse_options(int argc, char **argv)
{
	int i, c, numfiles;

	if (argc < 2)
		return 1;

	while ((c = getopt(argc, argv, "b:vdDrh?")) != -1) {
		switch (c) {
		case 'b':
			blocksize = atoi(optarg);
			blocksize *= 1024;
			if (blocksize < MIN_BLOCKSIZE ||
			    blocksize > MAX_BLOCKSIZE)
				return EINVAL;
			break;
		case 'D':
			run_dedupe = 1;
			break;
		case 'r':
			recurse_dirs = 1;
			break;
		case 'd':
			debug = 1;
			/* Fall through */
		case 'v':
			verbose = 1;
			break;
		case 'h':
		case '?':
		default:
			return 1;
		}
	}

	numfiles = argc - optind;

	for (i = 0; i < numfiles; i++) {
		const char *name = argv[i + optind];

		add_file(name, AT_FDCWD);
	}

	/* This can happen if for example, all files passed in on
	 * command line are bad. */
	if (list_empty(&filerec_list))
		return EINVAL;

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

struct dupe_walk_ctxt {
	struct file_block	*orig;

	struct filerec		*orig_file;
	struct filerec		*walk_file;

	struct results_tree	*res;
};

static int walk_dupe_block(struct file_block *block, void *priv)
{
	struct dupe_walk_ctxt *ctxt = priv;
	struct file_block *orig = ctxt->orig;
	struct file_block *start[2] = { orig, block };
	struct file_block *end[2];
	struct running_checksum *csum;
	unsigned char match_id[DIGEST_LEN_MAX] = {0, };

	if (block_seen(block))
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
		if (orig->b_file_next.next == &ctxt->orig_file->block_list ||
		    block->b_file_next.next == &ctxt->walk_file->block_list)
			break;

		orig =	list_entry(orig->b_file_next.next, struct file_block,
				   b_file_next);
		block =	list_entry(block->b_file_next.next, struct file_block,
				   b_file_next);
	}

	finish_running_checksum(csum, match_id);

	record_match(ctxt->res, match_id, ctxt->orig_file, ctxt->walk_file,
		     start, end);
out:
	return 0;
}

static void find_file_dupes(struct filerec *file, struct filerec *walk_file,
			    struct results_tree *res)
{
	struct file_block *cur;
	struct dupe_walk_ctxt ctxt = { 0, };

	list_for_each_entry(cur, &file->block_list, b_file_next) {
		if (block_seen(cur))
			continue;
		/*
		 * For each file block with the same hash:
		 *  - Traverse, along with original file until we have no match
		 *     - record
		 */
		memset(&ctxt, 0, sizeof(struct dupe_walk_ctxt));
		ctxt.orig_file = file;
		ctxt.walk_file = walk_file;
		ctxt.orig = cur;
		ctxt.res = res;
		for_each_dupe(cur, walk_file, walk_dupe_block, &ctxt);
	}
	clear_all_seen_blocks();
}

int main(int argc, char **argv)
{
	int ret;
	struct hash_tree tree;
	struct results_tree res;
	struct filerec *file, *file1, *file2;

	if (init_hash())
		return ENOMEM;

	init_filerec();
	init_hash_tree(&tree);
	init_results_tree(&res);

	if (parse_options(argc, argv)) {
		usage(argv[0]);
		return EINVAL;
	}

	vprintf("Using %uK blocks\n", blocksize/1024);

	buf = malloc(blocksize);
	if (!buf)
		return ENOMEM;

	ret = populate_hash_tree(&tree);
	if (ret) {
		fprintf(stderr, "Error while populating extent tree!\n");
		goto out;
	}

	debug_print_tree(&tree);

	list_for_each_entry(file1, &filerec_list, rec_list) {
		file2 = file1;
		list_for_each_entry_from(file2, &filerec_list, rec_list) {
			find_file_dupes(file1, file2, &res);
		}
	}

	if (debug) {
		print_results(&res);
		printf("\n\nRemoving overlapping extents\n\n");
	}

	list_for_each_entry(file, &filerec_list, rec_list) {
		remove_overlapping_extents(&res, file);
	}

	if (run_dedupe)
		dedupe_results(&res);
	else
		print_results(&res);

out:
	return ret;
}
