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
#include <unistd.h>

#include <glib.h>

#include "list.h"
#include "csum.h"
#include "filerec.h"
#include "hash-tree.h"
#include "results-tree.h"
#include "dedupe.h"
#include "util.h"
#include "btrfs-util.h"
#include "dbfile.h"
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
int block_dedupe = 0;
int dedupe_same_file = 0;
int skip_zeroes = 0;

int target_rw = 1;
static int version_only = 0;
static int fdupes_mode = 0;

static enum {
	H_READ,
	H_WRITE,
	H_UPDATE,
} use_hashfile = H_UPDATE;
static char *serialize_fname = NULL;
unsigned int io_threads;
int do_lookup_extents = 1;

int stdout_is_tty = 0;

static char *user_hash = DEFAULT_HASH_STR;

static void usage(const char *prog)
{
	printf("duperemove %s\n", VERSTRING);
	if (version_only)
		return;

	printf("Find duplicate extents and print them to stdout\n\n");
	printf("Usage: %s [-r] [-d] [-h] [--debug] [--hashfile=hashfile]"
	       " OBJECTS\n", prog);
	printf("\n\"OBJECTS\" is a list of files (or directories) which we\n");
	printf("want to find duplicate extents in. If a directory is \n");
	printf("specified, all regular files inside of it will be scanned.\n");
	printf("\n\t<switches>\n");
	printf("\t-r\t\tEnable recursive dir traversal.\n");
	printf("\t-d\t\tDe-dupe the results - only works on btrfs.\n");
	printf("\t-h\t\tPrint numbers in human-readable format.\n");
	printf("\t--skip-zeroes\tdon't dedup zeroed blocks.\n");
	printf("\t--hashfile=FILE\tUse a file instead of memory for storing hashes.\n");
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

/* adapted from ocfs2-tools */
static int parse_dedupe_opts(const char *opts)
{
	char *options, *token, *next, *p, *arg;
	int print_usage = 0;
	int invert, ret = 0;

	options = strdup(opts);

	for (token = options; token && *token; token = next) {
		p = strchr(token, ',');
		next = NULL;
		invert = 0;

		if (p) {
			*p = '\0';
			next = p + 1;
		}

		arg = strstr(token, "no");
		if (arg == token) {
			invert = 1;
			token += strlen("no");
		}

		if (strcmp(token, "same") == 0) {
			dedupe_same_file = !invert;
		} else if (strcmp(token, "block") == 0) {
			block_dedupe = !invert;
		} else {
			print_usage = 1;
			break;
		}
	}

	if (print_usage) {
		fprintf(stderr, "Bad dedupe options specified. Valid dedupe "
			"options are:\n"
			"\t[no]same\n"
			"\t[no]block\n");
		ret = EINVAL;
	}

	free(options);
	return ret;
}

enum {
	DEBUG_OPTION = CHAR_MAX + 1,
	HELP_OPTION,
	VERSION_OPTION,
	WRITE_HASHES_OPTION,
	READ_HASHES_OPTION,
	HASHFILE_OPTION,
	IO_THREADS_OPTION,
	LOOKUP_EXTENTS_OPTION,
	ONE_FILESYSTEM_OPTION,
	HASH_OPTION,
	SKIP_ZEROES_OPTION,
	FDUPES_OPTION,
	DEDUPE_OPTS_OPTION,
};

static int add_files_from_stdin(int fdupes)
{
	int ret = 0;
	char *path = NULL;
	size_t pathlen = 0;
	ssize_t readlen;

	while ((readlen = getline(&path, &pathlen, stdin)) != -1) {
		if (readlen == 0)
			continue;

		if (fdupes && readlen == 1 && path[0] == '\n') {
			ret = fdupes_dedupe();
			if (ret)
				return ret;
			continue;
		}

		if (readlen > 0 && path[readlen - 1] == '\n') {
			path[--readlen] = '\0';
		}

		if (readlen > PATH_MAX - 1) {
			fprintf(stderr, "Path max exceeded: %s\n", path);
			continue;
		}

		if (add_file(path, AT_FDCWD))
			return 1;

		/* Give the user a chance to see some output from add_file(). */
		if (!fdupes)
			fflush(stdout);
	}

	if (path != NULL)
		free(path);

	return 0;
}

static int add_files_from_cmdline(int numfiles, char **files)
{
	int i;

	for (i = 0; i < numfiles; i++) {
		const char *name = files[i];

		if (add_file(name, AT_FDCWD))
			return 1;
	}

	return 0;
}

/*
 * Ok this is doing more than just parsing options.
 */
static int parse_options(int argc, char **argv)
{
	int c, numfiles;
	int read_hashes = 0;
	int write_hashes = 0;
	int update_hashes = 0;

	static struct option long_ops[] = {
		{ "debug", 0, NULL, DEBUG_OPTION },
		{ "help", 0, NULL, HELP_OPTION },
		{ "version", 0, NULL, VERSION_OPTION },
		{ "write-hashes", 1, NULL, WRITE_HASHES_OPTION },
		{ "read-hashes", 1, NULL, READ_HASHES_OPTION },
		{ "hashfile", 1, NULL, HASHFILE_OPTION },
		{ "io-threads", 1, NULL, IO_THREADS_OPTION },
		{ "hash-threads", 1, NULL, IO_THREADS_OPTION },
		{ "lookup-extents", 1, NULL, LOOKUP_EXTENTS_OPTION },
		{ "one-file-system", 0, NULL, ONE_FILESYSTEM_OPTION },
		{ "hash", 1, NULL, HASH_OPTION },
		{ "skip-zeroes", 0, NULL, SKIP_ZEROES_OPTION },
		{ "fdupes", 0, NULL, FDUPES_OPTION },
		{ "dedupe-options=", 1, NULL, DEDUPE_OPTS_OPTION },
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
			    blocksize > MAX_BLOCKSIZE){
				fprintf(stderr, "Error: Blocksize is bounded by %u and %u, %u found\n",
					MIN_BLOCKSIZE, MAX_BLOCKSIZE, blocksize);
				return EINVAL;
			}
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
		case HASHFILE_OPTION:
			update_hashes = 1;
			serialize_fname = strdup(optarg);
			break;
		case IO_THREADS_OPTION:
			io_threads = strtoul(optarg, NULL, 10);
			if (!io_threads){
				fprintf(stderr, "Error: --io-threads must be "
					"an integer, %s found\n", optarg);
				return EINVAL;
			}
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
		case SKIP_ZEROES_OPTION:
			skip_zeroes = 1;
			break;
		case FDUPES_OPTION:
			fdupes_mode = 1;
			break;
		case DEDUPE_OPTS_OPTION:
			if (parse_dedupe_opts(optarg))
				return EINVAL;
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
	if ((write_hashes + read_hashes + update_hashes) > 1) {
		fprintf(stderr, "Error: Specify only one hashfile option.\n");
		return 1;
	}

	if (read_hashes)
		use_hashfile = H_READ;
	else if (write_hashes)
		use_hashfile = H_WRITE;
	else if (update_hashes)
		use_hashfile = H_UPDATE;

	if (read_hashes) {
		if (numfiles) {
			fprintf(stderr,
				"Error: --read-hashes option does not take a "
				"file list argument\n");
			return 1;
		}
		goto out_nofiles;
	}

	if (fdupes_mode) {
		if (read_hashes || write_hashes || update_hashes) {
			fprintf(stderr,
				"Error: cannot mix hashfile option with "
				"--fdupes option\n");
			return 1;
		}

		if (numfiles) {
			fprintf(stderr,
				"Error: fdupes option does not take a file "
				"list argument\n");
			return 1;
		}
		/* rest of fdupes mode is implemented in main() */
		return 0;
	}

	if (numfiles == 1 && strcmp(argv[optind], "-") == 0) {
		if (add_files_from_stdin(0))
			return 1;
	} else {
		if (add_files_from_cmdline(numfiles, &argv[optind]))
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
	struct results_tree res;

	init_filerec();
	init_results_tree(&res);

	/* Parse options might change this so set a default here */
#if GLIB_CHECK_VERSION(2,36,0)
	io_threads = g_get_num_processors();
#else
	io_threads = sysconf(_SC_NPROCESSORS_ONLN);
#endif

	if (parse_options(argc, argv)) {
		usage(argv[0]);
		return EINVAL;
	}

	if (fdupes_mode)
		return add_files_from_stdin(1);

	ret = init_csum_module(user_hash);
	if (ret) {
		if (ret == EINVAL)
			fprintf(stderr,
				"Could not initialize hash module \"%s\"\n",
				user_hash);
		return ret;
	}

	if (isatty(STDOUT_FILENO))
		stdout_is_tty = 1;

	printf("Using %uK blocks\n", blocksize / 1024);
	printf("Using hash: %s\n", csum_mod->name);

	switch (use_hashfile) {
	case H_UPDATE:
	case H_WRITE:
		ret = dbfile_create(serialize_fname);
		if (ret)
			break;
		ret = populate_tree();
		break;
	case H_READ:
		ret = dbfile_open(serialize_fname);
		if (ret)
			break;
		/*
		 * Skips the file scan, used to isolate the
		 * extent-find and dedupe stages
		 */
		ret = dbfile_get_config(&blocksize, NULL, NULL, NULL, NULL);
		break;
	default:
		abort_lineno();
		break;
	}

	if (ret) {
		fprintf(stderr, "Error while populating extent tree!\n");
		goto out;
	}

	ret = create_indexes(dbfile_get_handle());
	if (ret)
		goto out;

	/*
	 * File scan from above can cause quite a bit of output, flush
	 * here in case of logfile.
	 */
	if (stdout_is_tty)
		fflush(stdout);

	if (use_hashfile == H_WRITE || use_hashfile == H_UPDATE) {
		ret = dbfile_sync_config(blocksize);
		if (ret)
			goto out;
		if (use_hashfile == H_WRITE) {
			/*
			 * This option is for isolating the file scan
			 * stage. Exit the program now.
			 */
			printf("Hashfile \"%s\" written, exiting.\n",
			       serialize_fname);
			goto out;
		}
	}

	/* We will now reread the serialized file, and create a new
	 * shiny tree with only duplicate hashes
	 */
	struct hash_tree dups_tree;

	printf("Loading only duplicated hashes from hashfile.\n");

	init_hash_tree(&dups_tree);

	ret = dbfile_load_hashes(&dups_tree);
	if (ret)
		goto out;

	/*
	 * Only error for this is enomem so we continue in the hopes
	 * that something might get deduped.
	 */
	ret = find_all_dupes(&dups_tree, &res);

	if (run_dedupe) {
		dedupe_results(&res, &dups_tree);
	} else {
		if (block_dedupe)
			debug_print_hash_tree(&dups_tree);
		else
			print_dupes_table(&res);
	}

	free_all_filerecs();
out:
	dbfile_close();

	if (ret == ENOMEM || debug)
		print_mem_stats();

	return ret;
}
