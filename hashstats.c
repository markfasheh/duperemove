/*
 * hashstats.c
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
 */

#include <limits.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>

#include "csum.h"
#include "dbfile.h"
#include "file_scan.h"

unsigned int blocksize;
static bool print_all_hashes = false;
static bool print_blocks = false;
static bool show_block_hashes = false;
static int num_to_print = 10;
static bool print_file_list = false;
static char *serialize_fname = NULL;

static int print_all_blocks(struct dbhandle *db, unsigned char *digest)
{
	int ret;
	uint64_t loff;
	const unsigned char *filename;
	_cleanup_(sqlite3_reset_stmt) sqlite3_stmt *find_blocks_stmt = db->stmts.find_blocks;

	ret = sqlite3_bind_blob(find_blocks_stmt, 1, digest, DIGEST_LEN,
				SQLITE_STATIC);
	if (ret) {
		fprintf(stderr, "Error %d binding digest for blocks: %s\n", ret,
			sqlite3_errstr(ret));
		return ret;
	}

	while ((ret = sqlite3_step(find_blocks_stmt)) == SQLITE_ROW) {
		filename = sqlite3_column_text(find_blocks_stmt, 0);
		loff = sqlite3_column_int64(find_blocks_stmt, 1);

		printf("  %s\tloff: %llu lblock: %llu", filename,
		       (unsigned long long)loff,
		       (unsigned long long)loff / blocksize);
	}
	if (ret != SQLITE_DONE) {
		fprintf(stderr,
			"error %d running block stmt: %s\n",
			ret, sqlite3_errstr(ret));
		return ret;
	}

	return 0;
}

static void print_by_size(struct dbhandle *db)
{
	int ret;
	int header_printed = 0;
	unsigned char *digest;
	uint64_t count, files_count;

	_cleanup_(sqlite3_reset_stmt) sqlite3_stmt *top_hashes_stmt;

	if (show_block_hashes)
		top_hashes_stmt = db->stmts.find_top_b_hashes;
	else
		top_hashes_stmt = db->stmts.find_top_e_hashes;

	if (print_all_hashes)
		printf("Print all hashes ");
	else
		printf("Print top %d hashes ", num_to_print);

	printf("(this may take some time)\n");

	while ((ret = sqlite3_step(top_hashes_stmt)) == SQLITE_ROW) {
		digest = (unsigned char *)sqlite3_column_blob(top_hashes_stmt, 0);
		count = sqlite3_column_int64(top_hashes_stmt, 1);

		files_count = count_file_by_digest(db, digest, show_block_hashes);

		if (!header_printed) {
			printf("Hash, # Blocks, # Files\n");
			header_printed = 1;
		}

		debug_print_digest(stdout, digest);
		printf(", %"PRIu64", %"PRIu64"\n", count, files_count);

		if (print_blocks) {
			ret = print_all_blocks(db, digest);
			if (ret)
				return;
		}

		if (!print_all_hashes && --num_to_print == 0) {
			ret = SQLITE_DONE;
			break;
		}
	}
	if (ret != SQLITE_DONE) {
		fprintf(stderr, "error %d retrieving hashes from table: %s\n",
			ret, sqlite3_errstr(ret));
	}
}

static int print_files_cb(void *priv [[maybe_unused]], int argc,
		char **argv, char **column [[maybe_unused]])
{
	int i;
	for(i = 0; i < argc; i++)
		printf("%s\t", argv[i]);
	printf("\n");
	return 0;
}

static void print_file_info(char *fname, struct dbfile_config *cfg,
				struct dbfile_stats *stats)
{
	printf("Raw header info for \"%s\":\n", fname);
	printf("  version: %d.%d\tblock_size: %u\n", cfg->major,
	       cfg->minor, cfg->blocksize);
	printf("  num_files: %"PRIu64"\tnum_block_hashes: %"PRIu64"\tnum_extent_hashes: %"PRIu64"\n",
	       stats->num_files, stats->num_b_hashes, stats->num_e_hashes);
}

static void version(void)
{
	printf("hashstats %s\n", VERSTRING);
}

static void usage(const char *prog)
{
	version();
	printf("Print information about duperemove hashes.\n\n");
	printf("Usage: %s [-n NUM] [-a] [-b] [-l] hashfile\n", prog);
	printf("Where \"hashfile\" is a file generated by running duperemove\n");
	printf("with the '--write-hashes' option. By default a list of hashes\n");
	printf("with the most shared blocks are printed.\n");
	printf("\n\t<switches>\n");
	printf("\t-n NUM\t\tPrint top N hashes, sorted by bucket size.\n");
	printf("\t      \t\tDefault is 10.\n");
	printf("\t-a\t\tPrint all hashes (overrides '-n', above)\n");
	printf("\t-B\t\tShow block hashes, and not extents-hashes\n");
	printf("\t-b\t\tPrint info on each block within our hash buckets\n");
	printf("\t-l\t\tPrint a list of all files\n");
	printf("\t--help\t\tPrints this help text.\n");
}

enum {
	HELP_OPTION = CHAR_MAX + 1,
	VERSION_OPTION,
	HASH_OPTION,
};

static int parse_options(int argc, char **argv)
{
	int c;
	static struct option long_ops[] = {
		{ "help", 0, 0, HELP_OPTION },
		{ "version", 0, 0, VERSION_OPTION },
		{ 0, 0, 0, 0}
	};

	if (argc < 2)
		return 1;

	while ((c = getopt_long(argc, argv, "laBbn:?", long_ops, NULL))
	       != -1) {
		switch (c) {
		case 'l':
			print_file_list = true;
			break;
		case 'a':
			print_all_hashes = true;
			break;
		case 'B':
			show_block_hashes = true;
			break;
		case 'b':
			print_blocks = true;
			break;
		case 'n':
			num_to_print = atoi(optarg);
			break;
		case VERSION_OPTION:
			version();
			exit(0);
		case HELP_OPTION:
		case '?':
		default:
			return 1;
		}
	}

	if ((argc - optind) != 1)
		return 1;

	serialize_fname = argv[optind];

	return 0;
}

int main(int argc, char **argv)
{
	int ret;
	struct dbfile_config dbfile_cfg;
	struct dbfile_stats dbfile_stats;

	if (parse_options(argc, argv)) {
		usage(argv[0]);
		return EINVAL;
	}

	_cleanup_(sqlite3_close_cleanup) struct dbhandle *db = dbfile_open_handle(serialize_fname);
	if (!db) {
		fprintf(stderr, "ERROR: Couldn't open db file %s\n",
			serialize_fname);
		return ENOMEM;
	}

	ret = dbfile_get_config(db->db, &dbfile_cfg);
	if (ret)
		return ret;

	ret = dbfile_get_stats(db, &dbfile_stats);
	if (ret)
		return ret;

	blocksize = dbfile_cfg.blocksize;
	print_file_info(serialize_fname, &dbfile_cfg, &dbfile_stats);

	if (num_to_print || print_all_hashes)
		print_by_size(db);

	if (print_file_list) {
		printf("Showing %"PRIu64" files.\nInode\tSubvol ID\tSize\tFilename\n",
			dbfile_stats.num_files);
		dbfile_list_files(db, print_files_cb);
	}

	return ret;
}
