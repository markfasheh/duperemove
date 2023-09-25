/*
 * opt.c
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

#include "opt.h"

struct options options = {
	.rescan_files = true,
	.run_dedupe = 0,
	.recurse_dirs = false,
	.io_threads = 0,
	.cpu_threads = 0,
	.skip_zeroes = false,
	.only_whole_files = false,
	.do_block_hash = false,
	.dedupe_same_file = true,
	.batch_size = 1024,
	.fdupes_mode = false,
};
