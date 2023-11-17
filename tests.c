#include <stdbool.h>
#include <sys/stat.h>

#include "minunit.h"
#include "rbtree.c"

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
#include "find_dupes.c"
#include "memstats.c"
#include "fiemap.c"


unsigned int blocksize = DEFAULT_BLOCKSIZE;

MU_TEST(test_is_block_zeroed) {
	char block[100] = {0,};
	// Actual zeroed block
	mu_check(is_block_zeroed(&block, 100) == true);

	// Block has the same content, but not zeroed
	memset(block, 1, 100);
	mu_check(is_block_zeroed(&block, 100) == false);

	// Block do not have the same content
	block[50] = 50;
	mu_check(is_block_zeroed(NULL, 100) == false);
}

MU_TEST(test_block_len) {
	struct file_block block;
	struct filerec file;

	block.b_file = &file;

	// First block of the file
	file.size = 10 * 1024 * 1024;
	block.b_loff = 0;
	mu_check(block_len(&block) == blocksize);

	// block in the middle of the file, unaligned
	block.b_loff = 1;
	mu_check(block_len(&block) == blocksize);

	// block in the middle of the file, aligned
	block.b_loff = blocksize * 10;
	mu_check(block_len(&block) == blocksize);

	// block at the end of the file, which is aligned
	file.size = blocksize * 10;
	block.b_loff = blocksize * 9;
	mu_check(block_len(&block) == blocksize);

	// block at the end of the file, which is unaligned
	unsigned int extra = 10;
	file.size = blocksize * 10 + extra;
	block.b_loff = blocksize * 10;
	mu_check(block_len(&block) == extra);

	// loff is passed filesize
	file.size = blocksize * 10 + extra;
	block.b_loff = blocksize * 15;
	mu_check(block_len(&block) == 0);
}

MU_TEST_SUITE(test_suite) {
	MU_RUN_TEST(test_is_block_zeroed);
	MU_RUN_TEST(test_block_len);
}

int main() {
	MU_RUN_SUITE(test_suite);
	MU_REPORT();
	return MU_EXIT_CODE;
}
