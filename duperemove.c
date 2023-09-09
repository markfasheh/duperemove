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

#include "list.h"
#include "csum.h"
#include "filerec.h"
#include "hash-tree.h"
#include "results-tree.h"
#include "dedupe.h"
#include "util.h"
#include "btrfs-util.h"
#include "dbfile.h"
#include "stats.h"
#include "memstats.h"
#include "debug.h"

#include "file_scan.h"
#include "find_dupes.h"
#include "run_dedupe.h"

#define MIN_BLOCKSIZE	(4U*1024)
/* max blocksize is somewhat arbitrary. */
#define MAX_BLOCKSIZE	(1024U*1024)
#define DEFAULT_BLOCKSIZE	(128U*1024)
unsigned int blocksize = DEFAULT_BLOCKSIZE;

int run_dedupe = 0;
int recurse_dirs = 0;
int v2_hashfile = 0;
int dedupe_same_file = 1;
int skip_zeroes = 0;

unsigned int batch_size = 0;

int target_rw = 1;
static int version_only = 0;
static int help_option = 0;
static int fdupes_mode = 0;
static int stdin_filelist = 0;
static unsigned int list_only_opt = 0;
static unsigned int rm_only_opt = 0;
struct dbfile_config dbfile_cfg;
static bool force_v2_hashfile = false;
static int partial_extent_search = 0;

static enum {
	H_READ,
	H_WRITE,
	H_UPDATE,
} use_hashfile = H_UPDATE;
char *serialize_fname = NULL;
static unsigned int nr_logical_cpus;
static unsigned int nr_physical_cpus;
unsigned int io_threads;
unsigned int cpu_threads;
int io_threads_opt = 0;
int cpu_threads_opt = 0;
int do_lookup_extents = 1;
int fiemap_during_dedupe = 1;
bool rescan_files = true;

int stdout_is_tty = 0;
bool do_block_hash = false;

static void print_file(char *filename, char *ino, char *subvol)
{
	if (verbose)
		printf("%s\t%s\t%s\n", filename, ino, subvol);
	else
		printf("%s\n", filename);
}

static int list_db_files(char *filename)
{
	int ret;

	ret = dbfile_open(filename, &dbfile_cfg);
	if (ret) {
		fprintf(stderr, "Error: Could not open \"%s\"\n", filename);
		return ret;
	}

	ret = dbfile_iter_files(dbfile_get_handle(), &print_file);

	dbfile_close();
	return ret;
}

struct rm_file {
	char *filename;
	struct list_head list;
};
static LIST_HEAD(rm_files_list);

static void add_rm_file(const char *filename)
{
	struct rm_file *rm = malloc(sizeof(*rm));
	if (rm) {
		rm->filename = strdup(filename);
		list_add_tail(&rm->list, &rm_files_list);
	}
}

static void free_rm_file(struct rm_file *rm)
{
	if (rm) {
		list_del(&rm->list);
		free(rm->filename);
		free(rm);
	}
}

static void add_rm_db_files_from_stdin(void)
{
	char *path = NULL;
	size_t pathlen = 0;
	ssize_t readlen;

	while ((readlen = getline(&path, &pathlen, stdin)) != -1) {
		if (readlen == 0)
			continue;

		if (readlen > 0 && path[readlen - 1] == '\n') {
			path[--readlen] = '\0';
		}

		if (readlen > PATH_MAX - 1) {
			fprintf(stderr, "Path max exceeded: %s\n", path);
			continue;
		}

		add_rm_file(path);
	}

	if (path != NULL)
		free(path);
}

static int rm_db_files(char *dbfilename)
{
	int ret, err = 0;
	struct rm_file *rm, *tmp;

	ret = dbfile_open(dbfilename, &dbfile_cfg);
	if (ret) {
		fprintf(stderr, "Error: Could not open \"%s\"\n", dbfilename);
		return ret;
	}

restart:
	list_for_each_entry_safe(rm, tmp, &rm_files_list, list) {
		if (strlen(rm->filename) == 1 && rm->filename[0] == '-') {
			add_rm_db_files_from_stdin();
			free_rm_file(rm);
			/*
			 * We may have added to the end of the list
			 * which messes up the next-entry condition
			 * for list_for_each_entry_safe()
			 */
			goto restart;
		}
		ret = dbfile_remove_file(dbfile_get_handle(), &dbfile_cfg,
					 rm->filename);
		if (ret == 0)
			vprintf("Removed \"%s\" from hashfile.\n",
				rm->filename);
		if (ret && ret != ENOENT && !err)
			err = ret;

		free_rm_file(rm);
	}

	dbfile_close();

	return err;
}

extern struct list_head exclude_list;

static void add_exclude_pattern(const char *pattern)
{
	struct exclude_file *exclude = malloc(sizeof(*exclude));
	if (exclude) {
		exclude->pattern = strdup(pattern);
		list_add_tail(&exclude->list, &exclude_list);
	}
}

static void print_version()
{
	char *s = NULL;
#ifdef	DEBUG_BUILD
	s = " (debug build)";
#endif
	printf("duperemove %s%s\n", VERSTRING, s ? s : "");
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
		} else if (strcmp(token, "fiemap") == 0) {
			fiemap_during_dedupe = !invert;
		} else if (strcmp(token, "partial") == 0) {
			partial_extent_search = !invert;
		} else if (strcmp(token, "rescan_files") == 0) {
			rescan_files = !invert;
		} else {
			print_usage = 1;
			break;
		}
	}

	if (print_usage) {
		fprintf(stderr, "Bad dedupe options specified. Valid dedupe "
			"options are:\n"
			"\t[no]same\n"
			"\t[no]fiemap\n"
			"\t[no]partial\n");
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
	WRITE_OLD_HASHES_OPTION,
	READ_HASHES_OPTION,
	HASHFILE_OPTION,
	IO_THREADS_OPTION,
	CPU_THREADS_OPTION,
	LOOKUP_EXTENTS_OPTION,
	SKIP_ZEROES_OPTION,
	FDUPES_OPTION,
	DEDUPE_OPTS_OPTION,
	QUIET_OPTION,
	EXCLUDE_OPTION,
	BATCH_SIZE_OPTION,
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

		if (add_file(path))
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

		if (add_file(name))
			return 1;
	}

	return 0;
}

/*
 * Ok this is doing more than just parsing options.
 */
static int parse_options(int argc, char **argv, int *filelist_idx)
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
		{ "write-hashes-v2", 1, NULL, WRITE_OLD_HASHES_OPTION },
		{ "read-hashes", 1, NULL, READ_HASHES_OPTION },
		{ "hashfile", 1, NULL, HASHFILE_OPTION },
		{ "io-threads", 1, NULL, IO_THREADS_OPTION },
		{ "hash-threads", 1, NULL, IO_THREADS_OPTION },
		{ "cpu-threads", 1, NULL, CPU_THREADS_OPTION },
		{ "lookup-extents", 1, NULL, LOOKUP_EXTENTS_OPTION },
		{ "skip-zeroes", 0, NULL, SKIP_ZEROES_OPTION },
		{ "fdupes", 0, NULL, FDUPES_OPTION },
		{ "dedupe-options=", 1, NULL, DEDUPE_OPTS_OPTION },
		{ "quiet", 0, NULL, QUIET_OPTION },
		{ "exclude", 1, NULL, EXCLUDE_OPTION },
		{ "batchsize", 1, NULL, BATCH_SIZE_OPTION },
		{ NULL, 0, NULL, 0}
	};

	if (argc < 2) {
		help_option = 1;
		return 0;
	}

	while ((c = getopt_long(argc, argv, "Ab:vdDrh?LR:qB:", long_ops, NULL))
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
			run_dedupe += 1;
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
		case WRITE_OLD_HASHES_OPTION:
			force_v2_hashfile = true;
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
			io_threads_opt = 1;
			break;
		case CPU_THREADS_OPTION:
			cpu_threads = strtoul(optarg, NULL, 10);
			if (!cpu_threads){
				fprintf(stderr, "Error: --cpu-threads must be "
					"an integer, %s found\n", optarg);
				return EINVAL;
			}
			cpu_threads_opt = 1;
			break;
		case LOOKUP_EXTENTS_OPTION:
			do_lookup_extents = parse_yesno_option(optarg, 0);
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
		case 'L':
			list_only_opt = 1;
			break;
		case 'R':
			rm_only_opt = 1;
			add_rm_file(optarg);
			break;
		case QUIET_OPTION:
		case 'q':
			quiet = 1;
			break;
		case EXCLUDE_OPTION:
			add_exclude_pattern(optarg);
			break;
		case BATCH_SIZE_OPTION:
		case 'B':
			batch_size = parse_size(optarg);
			break;
		case HELP_OPTION:
			help_option = 1;
			break;
		case '?':
		default:
			version_only = 0;
			return 1;
		}
	}

	if (!do_lookup_extents || !fiemap_during_dedupe)
		force_v2_hashfile = true;

	if (force_v2_hashfile || partial_extent_search)
		do_block_hash = true;

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

	*filelist_idx = 0;
	if (numfiles == 1 && strcmp(argv[optind], "-") == 0)
		stdin_filelist = 1;
	else {
		*filelist_idx = optind;
	}

	if (list_only_opt && rm_only_opt) {
		fprintf(stderr, "Error: Can not mix '-L' and '-R' options.\n");
		return 1;
	}

	if (list_only_opt || rm_only_opt) {
		if (!serialize_fname || use_hashfile == H_WRITE) {
			fprintf(stderr,	"Error: --hashfile= option is required "
				"with '-L' or -R.\n");
			return 1;
		}

		if (numfiles) {
			fprintf(stderr, "Error: -L and -R options do not take "
				"a file list argument\n");
			return 1;
		}
	}

	if ((use_hashfile == H_UPDATE || use_hashfile == H_WRITE)
			&& numfiles == 0) {
		fprintf(stderr, "Error: a file list argument is required.\n");
		return 1;
	}

out_nofiles:

	return 0;
}

static void print_header(void)
{
	vprintf("Using %uK blocks\n", blocksize / 1024);
	vprintf("Using %s hashing\n", v2_hashfile ? "block-based" : "extent-based");
#ifdef	DEBUG_BUILD
	printf("Debug build, performance may be impacted.\n");
#endif
	qprintf("Gathering file list...\n");
}

static int update_config_from_dbfile(void)
{
	dedupe_seq = dbfile_cfg.dedupe_seq;

	if (strncasecmp(dbfile_cfg.hash_type, HASH_TYPE, 8)) {
		fprintf(stderr,
			"Error: Hashfile %s uses \"%.*s\" for checksums "
			"but we are using %.*s.\nYou are probably "
			"using a hashfile generated from an old version, "
			"which cannot be read anymore.\n", serialize_fname, 8,
			dbfile_cfg.hash_type, 8, HASH_TYPE);
		return EINVAL;
	}

	if (dbfile_cfg.blocksize != blocksize &&
	    dbfile_cfg.major == BLOCK_DEDUPE_DBFILE_VER) {
		vprintf("Using blocksize %uK from hashfile (%uK "
			"blocksize requested).\n", dbfile_cfg.blocksize/1024,
			blocksize/1024);
		blocksize = dbfile_cfg.blocksize;
	}

	return 0;
}

void process_duplicates() {
	int ret;
	struct results_tree res;
	struct hash_tree dups_tree;

	init_results_tree(&res);
	init_hash_tree(&dups_tree);

	qprintf("Loading only duplicated hashes from hashfile.\n");

	if (v2_hashfile) {
		ret = dbfile_load_block_hashes(&dups_tree);
		if (ret)
			goto out;

		ret = find_all_dupes(&dups_tree, &res);
		if (ret) {
			/* Only error for this should be enomem */
			fprintf(stderr,
				"Error %d: %s while finding duplicate extents.\n",
				ret, strerror(ret));
			goto out;
		}
	} else {
		ret = dbfile_load_extent_hashes(&res);
		if (ret)
			goto out;

		printf("Found %llu identical extents.\n", res.num_extents);
		if (partial_extent_search) {
			ret = dbfile_load_block_hashes(&dups_tree);
			if (ret)
				goto out;

			ret = find_additional_dedupe(&res);
			if (ret)
				goto out;
		}
	}

	if (run_dedupe) {
		dedupe_results(&res);

		/*
		 * Bump dedupe_seq, this effectively marks the files
		 * in our hashfile as having been through dedupe.
		 */
		dedupe_seq++;

		/* Sync to get new dedupe_seq written. */
		dbfile_cfg.dedupe_seq = dedupe_seq;
		dbfile_cfg.blocksize = blocksize;
		dbfile_cfg.onefs_dev = fs_onefs_dev();
		dbfile_cfg.onefs_fsid = fs_onefs_id();
		ret = dbfile_sync_config(&dbfile_cfg);
		if (ret)
			goto out;
	} else {
		print_dupes_table(&res);
	}

out:
	free_results_tree(&res);
	free_hash_tree(&dups_tree);
}



static int create_update_hashfile(int argc, char **argv, int filelist_idx)
{
	int ret;
	int dbfile_is_new = 0;

	ret = dbfile_create(serialize_fname, &dbfile_is_new,
			    force_v2_hashfile ? BLOCK_DEDUPE_DBFILE_VER : DB_FILE_MAJOR,
			    &dbfile_cfg);
	if (ret)
		goto out;

	if (force_v2_hashfile && dbfile_cfg.major != BLOCK_DEDUPE_DBFILE_VER) {
		ret = EINVAL;
		fprintf(stderr, "Error: asked to force hashfile version 2 but "
			"existing hashfile has version %d\n", dbfile_cfg.major);
		goto out;
	}

	if (dbfile_cfg.major == BLOCK_DEDUPE_DBFILE_VER)
		v2_hashfile = 1;

	if (!dbfile_is_new) {
		ret = update_config_from_dbfile();
		if (ret)
			goto out;
		fs_set_onefs(dbfile_cfg.onefs_dev, dbfile_cfg.onefs_fsid);
	}

	print_header();

	if (stdin_filelist)
		ret = add_files_from_stdin(0);
	else
		ret = add_files_from_cmdline(argc - filelist_idx,
					     &argv[filelist_idx]);
	if (ret)
		goto out;

	if (dbfile_is_new) {
		dbfile_cfg.blocksize = blocksize;
		dbfile_cfg.onefs_dev = fs_onefs_dev();
		dbfile_cfg.onefs_fsid = fs_onefs_id();
		dbfile_cfg.dedupe_seq = dedupe_seq;
		ret = dbfile_sync_config(&dbfile_cfg);
		if (ret)
			goto out;
	} else {
		qprintf("Adding files from database for hashing.\n");

		ret = dbfile_scan_files(&dbfile_cfg);
		if (ret)
			goto out;
	}

	if (list_empty(&filerec_list)) {
		fprintf(stderr, "No dedupe candidates found.\n");
		ret = EINVAL;
		goto out;
	}

	ret = create_indexes(dbfile_get_handle(), &dbfile_cfg);
	if (ret)
		goto out;

	ret = populate_tree(&dbfile_cfg, batch_size, &process_duplicates);
	if (ret) {
		fprintf(stderr,	"Error while populating extent tree!\n");
		goto out;
	}

	/*
	 * File scan from above can cause quite a bit of output, flush
	 * here in case of logfile.
	 */
	if (stdout_is_tty)
		fflush(stdout);

	ret = dbfile_sync_files(dbfile_get_handle());
	if (ret)
		goto out;
out:
	return ret;
}

int main(int argc, char **argv)
{
	int ret, filelist_idx = 0;

	init_filerec();

	ret = parse_options(argc, argv, &filelist_idx);
	if (ret) {
		exit(1);
	}

	if (version_only) {
		print_version();
		exit(0);
	}

	if (help_option) {
		execlp("man", "man", "8", "duperemove", NULL);
	}

	/* Allow larger than unusal amount of open files. On linux
	 * this should bw increase form 1K to 512K open files
	 * simultaneously.
	 *
	 * On multicore SSD machines it's not hard to get to 1K open
	 * files.
	 */
	increase_limits();
	/*
	 * Don't run detection if the user has supplied our cpu counts
	 * already.
	 */
	if (!io_threads_opt || !cpu_threads_opt) {
		get_num_cpus(&nr_physical_cpus, &nr_logical_cpus);
		if (!io_threads)
			io_threads = nr_logical_cpus;
		if (!cpu_threads)
			cpu_threads = nr_physical_cpus;
	}

	if (fdupes_mode)
		return add_files_from_stdin(1);

	if (isatty(STDOUT_FILENO))
		stdout_is_tty = 1;

	if (list_only_opt)
		return list_db_files(serialize_fname);
	else if (rm_only_opt)
		return rm_db_files(serialize_fname);

	switch (use_hashfile) {
	case H_UPDATE:
	case H_WRITE:
		if (serialize_fname && !IS_RELEASE)
			printf("Warning: The hash file format in Duperemove "
			       "master branch is under development and may "
			       "change.\nIf the changes are not backwards "
			       "compatible, you will have to re-create your "
			       "hash file.\n");
		ret = create_update_hashfile(argc, argv, filelist_idx);
		if (ret)
			goto out;

		if (use_hashfile == H_WRITE) {
			/*
			 * This option is for isolating the file scan
			 * stage. Exit the program now.
			 */
			qprintf("Hashfile \"%s\" written, exiting.\n",
				serialize_fname);
			goto out;
		}
		break;
	case H_READ:
		ret = dbfile_open(serialize_fname, &dbfile_cfg);
		if (ret) {
			fprintf(stderr, "Error: Could not open dbfile %s.\n",
				serialize_fname);
			goto out;
		}

		if (dbfile_cfg.major == BLOCK_DEDUPE_DBFILE_VER)
			v2_hashfile = 1;

		/*
		 * Skips the file scan, used to isolate the
		 * extent-find and dedupe stages
		 */
		blocksize = dbfile_cfg.blocksize;
		ret = update_config_from_dbfile();
		if (ret)
			goto out;

		print_header();

		process_duplicates();
		break;
	default:
		abort_lineno();
		break;
	}

#ifdef	PRINT_STATS
	run_filerec_stats();
#endif

out:
	free_all_filerecs();
	dbfile_close();

#ifdef DEBUG_BUILD
	print_mem_stats();
#else
	if (ret == ENOMEM || debug)
		print_mem_stats();
#endif

	return ret;
}
