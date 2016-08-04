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

#include "memstats.h"

void print_mem_stats(void)
{
	printf("Duperemove memory usage statistics:\n");
	show_allocs_file_block();
	show_allocs_dupe_blocks_list();
	show_allocs_dupe_extents();
	show_allocs_extent();
	show_allocs_filerec();
	show_allocs_filerec_token();
	show_allocs_file_hash_head();
}
