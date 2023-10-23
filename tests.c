#include <stdbool.h>
#include <sys/stat.h>

#include "minunit.h"
#include "rbtree.c"
#include "csum-xxhash.c"

#include "opt.c"
#include "util.c"
#include "debug.c"
#include "csum.c"
#include "threads.c"
#include "btrfs-util.c"
#include "file_scan.c"
#include "filerec.c"
#include "dbfile.c"
#include "hash-tree.c"
#include "results-tree.c"
#include "list_sort.c"


unsigned int blocksize;

MU_TEST(test_is_block_zeroed) {
	char block[100] = {0,};
	// Actual zeroed block
	mu_check(is_block_zeroed(&block, 100) == true);

	// Block has the same content, but not zeroed
	memset(block, 1, 100);
	mu_check(is_block_zeroed(&block, 100) == false);

	// Block do not have the same content
	block[50] = 50;
	mu_check(is_block_zeroed(NULL, 0) == false);
}

MU_TEST_SUITE(test_suite) {
	MU_RUN_TEST(test_is_block_zeroed);
}

int main() {
	MU_RUN_SUITE(test_suite);
	MU_REPORT();
	return MU_EXIT_CODE;
}
