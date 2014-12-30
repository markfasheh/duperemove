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
#include "run_dedupe.h"

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

int target_rw = 1;
static int version_only = 0;

static int write_hashes = 0;
static int read_hashes = 0;
static char *serialize_fname = NULL;
unsigned int io_threads;
int do_lookup_extents = 0;

int fancy_status = 0;

static char *user_hash = DEFAULT_HASH_STR;

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
	IO_THREADS_OPTION,
	LOOKUP_EXTENTS_OPTION,
	ONE_FILESYSTEM_OPTION,
	HASH_OPTION,
};

/*
 * Ok this is doing more than just parsing options.
 */
static int parse_options(int argc, char **argv)
{
	int i, c, numfiles;
	static struct option long_ops[] = {
		{ "debug", 0, NULL, DEBUG_OPTION },
		{ "help", 0, NULL, HELP_OPTION },
		{ "version", 0, NULL, VERSION_OPTION },
		{ "write-hashes", 1, NULL, WRITE_HASHES_OPTION },
		{ "read-hashes", 1, NULL, READ_HASHES_OPTION },
		{ "io-threads", 1, NULL, IO_THREADS_OPTION },
		{ "hash-threads", 1, NULL, IO_THREADS_OPTION },
		{ "lookup-extents", 1, NULL, LOOKUP_EXTENTS_OPTION },
		{ "one-file-system", 0, NULL, ONE_FILESYSTEM_OPTION },
		{ "hash", 1, NULL, HASH_OPTION },
		{ NULL, 0, NULL, 0}
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
		case IO_THREADS_OPTION:
			io_threads = strtoul(optarg, NULL, 10);
			if (!io_threads)
				return EINVAL;
			break;
		case LOOKUP_EXTENTS_OPTION:
			do_lookup_extents = parse_yesno_option(optarg, 0);
			break;
		case ONE_FILESYSTEM_OPTION:
		case 'x':
			one_file_system = 1;
			break;
		case HASH_OPTION:
			user_hash = optarg;
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

	if (numfiles == 1 && strcmp(argv[optind], "-") == 0) {
		char *path = NULL;
		size_t pathlen = 0;
		ssize_t readlen;

		while ((readlen = getline(&path, &pathlen, stdin)) != -1) {
			if (readlen > 0 && path[readlen - 1] == '\n') {
				path[--readlen] = '\0';
			}

			if (readlen == 0)
				continue;

			if (readlen > PATH_MAX - 1) {
				fprintf(stderr, "Path max exceeded: %s\n", path);
				continue;
			}

			if (add_file(path, AT_FDCWD))
				return 1;
		}

		if (path != NULL)
			free(path);
	} else {
		for (i = 0; i < numfiles; i++) {
			const char *name = argv[i + optind];

			if (add_file(name, AT_FDCWD))
				return 1;
		}
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

	init_filerec();
	init_hash_tree(&tree);
	init_results_tree(&res);

	/* Parse options might change this so set a default here */
	io_threads = g_get_num_processors();

	if (parse_options(argc, argv)) {
		usage(argv[0]);
		return EINVAL;
	}

	ret = init_csum_module(user_hash);
	if (ret) {
		if (ret == EINVAL)
			fprintf(stderr,
				"Could not initialize hash module \"%s\"\n",
				user_hash);
		return ret;
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
	printf("Using hash: %s\n", csum_mod->name);

	if (!read_hashes) {
		ret = populate_hash_tree(&tree);
		if (ret) {
			fprintf(stderr, "Error while populating extent tree!\n");
			goto out;
		}
	}

	debug_print_hash_tree(&tree);

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

	free_all_filerecs();
out:
	if (ret == ENOMEM || debug)
		print_mem_stats();

	return ret;
}
