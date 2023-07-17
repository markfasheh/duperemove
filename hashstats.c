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

#include "csum.h"
#include "dbfile.h"
#include "file_flags.h"

unsigned int blocksize;
int v2_hashfile = 0;
static int version_only = 0;
static int print_all_hashes = 0;
static int print_blocks = 0;
static int num_to_print = 10;
static int print_file_list = 0;
static char *serialize_fname = NULL;

/* dirty hack so we don't have to add file_scan.o to hashstats */
int add_file_db(const char *filename [[maybe_unused]],
		uint64_t inum [[maybe_unused]],
		uint64_t subvolid [[maybe_unused]],
		uint64_t size [[maybe_unused]],
		uint64_t mtime [[maybe_unused]],
		unsigned int seq [[maybe_unused]],
		int *delete [[maybe_unused]])
{
	return 0;
}

static void printf_file_block_flags(unsigned int flags)
{
	if (!flags)
		return;

	printf("( ");
	if (flags & FILE_BLOCK_SKIP_COMPARE)
		printf("skip_compare ");
	if (flags & FILE_BLOCK_DEDUPED)
		printf("deduped ");
	if (flags & FILE_BLOCK_HOLE)
		printf("hole ");
	if (flags & FILE_BLOCK_PARTIAL)
		printf("partial ");
	printf(")");
}

static int print_all_blocks(unsigned char *digest, sqlite3_stmt *find_blocks_stmt)
{
	int ret;
	uint64_t loff;
	unsigned int flags;
	const unsigned char *filename;

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
		flags = sqlite3_column_int(find_blocks_stmt, 2);

		printf("  %s\tloff: %llu lblock: %llu "
		       "flags: 0x%x ", filename,
		       (unsigned long long)loff,
		       (unsigned long long)loff / blocksize,
		       flags);
		printf_file_block_flags(flags);
		printf("\n");
	}
	if (ret != SQLITE_DONE) {
		fprintf(stderr,
			"error %d running block stmt: %s\n",
			ret, sqlite3_errstr(ret));
		return ret;
	}

	sqlite3_reset(find_blocks_stmt);

	return 0;
}

static void print_by_size(sqlite3 *db)
{
	int ret;
	int header_printed = 0;
	unsigned char *digest;
	uint64_t count, files_count;

	_cleanup_(sqlite3_stmt_cleanup) sqlite3_stmt *find_blocks_stmt = NULL;
	_cleanup_(sqlite3_stmt_cleanup) sqlite3_stmt *top_hashes_stmt = NULL;
	_cleanup_(sqlite3_stmt_cleanup) sqlite3_stmt *files_count_stmt = NULL;

#define	FIND_BLOCKS							\
"select files.filename, hashes.loff, hashes.flags from files INNER JOIN hashes on hashes.digest = ?1 AND files.subvol=hashes.subvol AND files.ino=hashes.ino;"

	ret = sqlite3_prepare_v2(db, FIND_BLOCKS, -1, &find_blocks_stmt, NULL);
	if (ret) {
		fprintf(stderr, "error %d while prepping find blocks stmt: %s\n",
			ret, sqlite3_errstr(ret));
		return;
	}

#define	FIND_TOP_HASHES							\
"select digest, count(digest) from hashes group by digest having (count(digest) > 1) order by (count(digest)) desc;"
	ret = sqlite3_prepare_v2(db, FIND_TOP_HASHES, -1, &top_hashes_stmt,
				 NULL);
	if (ret) {
		fprintf(stderr, "error %d while prepping hash search stmt: %s\n",
			ret, sqlite3_errstr(ret));
		return;
	}

#define	FIND_FILES_COUNT						\
"select count (distinct files.filename) from files INNER JOIN hashes on hashes.digest = ?1 AND files.subvol=hashes.subvol AND files.ino=hashes.ino;"
	ret = sqlite3_prepare_v2(db, FIND_FILES_COUNT, -1, &files_count_stmt,
				 NULL);
	if (ret) {
		fprintf(stderr, "error %d while preparing file count stmt: %s\n",
			ret, sqlite3_errstr(ret));
		return;
	}

	if (print_all_hashes)
		printf("Print all hashes ");
	else
		printf("Print top %d hashes ", num_to_print);

	printf("(this may take some time)\n");

	while ((ret = sqlite3_step(top_hashes_stmt)) == SQLITE_ROW) {
		digest = (unsigned char *)sqlite3_column_blob(top_hashes_stmt, 0);
		count = sqlite3_column_int64(top_hashes_stmt, 1);

		ret = sqlite3_bind_blob(files_count_stmt, 1, digest, DIGEST_LEN,
					SQLITE_STATIC);
		if (ret) {
			fprintf(stderr, "Error %d binding digest: %s\n", ret,
				sqlite3_errstr(ret));
			return;
		}

		ret = sqlite3_step(files_count_stmt);
		if (ret != SQLITE_ROW && ret != SQLITE_DONE) {
			fprintf(stderr, "error %d, file count search: %s\n",
				ret, sqlite3_errstr(ret));
			return;
		}

		files_count = sqlite3_column_int64(files_count_stmt, 0);

		if (!header_printed) {
			printf("Hash, # Blocks, # Files\n");
			header_printed = 1;
		}

		debug_print_digest(stdout, digest);
		printf(", %"PRIu64", %"PRIu64"\n", count, files_count);

		sqlite3_reset(files_count_stmt);

		if (print_blocks) {
			ret = print_all_blocks(digest, find_blocks_stmt);
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

static void print_file_info(char *fname, struct dbfile_config *cfg)
{
	printf("Raw header info for \"%s\":\n", fname);
	printf("  version: %d.%d\tblock_size: %u\n", cfg->major,
	       cfg->minor, cfg->blocksize);
	printf("  num_files: %"PRIu64"\tnum_hashes: %"PRIu64"\n",
	       cfg->num_files, cfg->num_hashes);
}

static void usage(const char *prog)
{
	printf("hashstats %s\n", VERSTRING);
	if (version_only)
		return;

	printf("Print information about duperemove hashes.\n\n");
	printf("Usage: %s [-n NUM] [-a] [-b] [-l] hashfile\n", prog);
	printf("Where \"hashfile\" is a file generated by running duperemove\n");
	printf("with the '--write-hashes' option. By default a list of hashes\n");
	printf("with the most shared blocks are printed.\n");
	printf("\n\t<switches>\n");
	printf("\t-n NUM\t\tPrint top N hashes, sorted by bucket size.\n");
	printf("\t      \t\tDefault is 10.\n");
	printf("\t-a\t\tPrint all hashes (overrides '-n', above)\n");
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

	while ((c = getopt_long(argc, argv, "labn:?", long_ops, NULL))
	       != -1) {
		switch (c) {
		case 'l':
			print_file_list = 1;
			break;
		case 'a':
			print_all_hashes = 1;
			break;
		case 'b':
			print_blocks = 1;
			break;
		case 'n':
			num_to_print = atoi(optarg);
			break;
		case VERSION_OPTION:
			version_only = 1;
			return 1;
		case HELP_OPTION:
		case '?':
		default:
			version_only = 0;
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

	if (parse_options(argc, argv)) {
		usage(argv[0]);
		return EINVAL;
	}

	struct sqlite3 *db = dbfile_open_handle(serialize_fname);
	if (!db) {
		fprintf(stderr, "ERROR: Couldn't open db file %s\n",
			serialize_fname);
		return ENOMEM;
	}

	ret = dbfile_get_config(db, &dbfile_cfg);
	if (ret)
		return ret;

	blocksize = dbfile_cfg.blocksize;
	print_file_info(serialize_fname, &dbfile_cfg);

	if (num_to_print || print_all_hashes)
		print_by_size(db);

	if (print_file_list) {
		printf("Showing %"PRIu64" files.\nInode\tSubvol ID\tBlocks Stored\tSize\tFilename\n",
			dbfile_cfg.num_files);
		dbfile_list_files(db, print_files_cb);
	}

	dbfile_close_handle(db);

	return ret;
}
