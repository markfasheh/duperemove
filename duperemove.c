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
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <inttypes.h>

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

#include "file_scan.h"
#include "find_dupes.h"

/* exported via debug.h */
int verbose = 0, debug = 0;

#define MIN_BLOCKSIZE	(4*1024)
/* max blocksize is somewhat arbitrary. */
#define MAX_BLOCKSIZE	(1024*1024)
#define DEFAULT_BLOCKSIZE	(128*1024)
unsigned int blocksize = DEFAULT_BLOCKSIZE;

int run_dedupe = 0;
int recurse_dirs = 0;
int one_file_system = 0;

static int target_rw = 1;
static int version_only = 0;

static int write_hashes = 0;
static int read_hashes = 0;
static char *serialize_fname = NULL;
unsigned int hash_threads = 0;
int do_lookup_extents = 1;

int fancy_status = 0;

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
	printf("\t--debug\t\tPrint debug messages, forces -v if selected.\n");
	printf("\t--help\t\tPrints this help text.\n");
	printf("\nPlease see the duperemove(8) manpage for more options.\n");
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
		ret = read_hash_tree(serialize_fname, &tree, &blocksize, NULL,
				     0);
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
		} else if (ret == FILE_HASH_TYPE_ERROR) {
			fprintf(stderr,
				"Hash file \"%s\": Unkown hash type \"%.*s\".\n"
				"(we use \"%.*s\").\n", serialize_fname,
				8, unknown_hash_type, 8, hash_type);
			goto out;
		} else if (ret) {
			fprintf(stderr, "Hash file \"%s\": "
				"Error %d while reading: %s.\n",
				serialize_fname, ret, strerror(ret));
			goto out;
		}
	}

	printf("Using %uK blocks\n", blocksize/1024);
	printf("Using hash: %.*s\n", 8, hash_type);

	if (!read_hashes) {
		ret = populate_hash_tree(&tree);
		if (ret) {
			fprintf(stderr, "Error while populating extent tree!\n");
			goto out;
		}
	}

	debug_print_tree(&tree);

	if (write_hashes) {
		ret = serialize_hash_tree(serialize_fname, &tree, blocksize);
		if (ret)
			fprintf(stderr, "Error %d while writing to hash file\n", ret);
		goto out;
	} else {
		printf("Hashed %"PRIu64" blocks, resulting in %"PRIu64" unique "
		       "hashes. Calculating duplicate extents - this may take "
		       "some time.\n", tree.num_blocks, tree.num_hashes);
	}

	ret = find_all_dupes(&tree, &res);
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
