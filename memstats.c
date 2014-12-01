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
}
