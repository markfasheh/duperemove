/*
 * memstats.c
 *
 * Copyright (C) 2016 SUSE.  All rights reserved.
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


#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <sqlite3.h>

#include "memstats.h"

void print_mem_stats(void)
{
	uint64_t sqlite3_highwater, sqlite3_memused;

	printf("Duperemove memory usage statistics:\n");
	show_allocs_file_block();
	show_allocs_dupe_blocks_list();
	show_allocs_dupe_extents();
	show_allocs_extent();
	show_allocs_extent_dedupe_info();
	show_allocs_filerec();
	show_allocs_filerec_token();
	show_allocs_file_hash_head();
	show_allocs_find_dupes_cmp();
	sqlite3_highwater = sqlite3_memory_highwater(0);
	sqlite3_memused = sqlite3_memory_used();
	printf("Sqlite3 used: %"PRIu64"  highwater: %"PRIu64"\n",
	       sqlite3_memused, sqlite3_highwater);
}
