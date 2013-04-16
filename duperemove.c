#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>

#include "rbtree.h"
#include "list.h"
#include "csum.h"
#include "hash-tree.h"
#include "results-tree.h"
#include "dedupe.h"

static int verbose = 0, debug = 0;
#define dprintf(args...)	if (debug) printf(args)
#define vprintf(args...)	if (verbose) printf(args)
#define abort_on(condition) do {					\
		if (condition) {					\
			printf("ERROR: %s:%d\n", __FILE__, __LINE__);\
			abort();					\
		}							\
	} while(0)

#define MIN_BLOCKSIZE	(4*1024)
/* max blocksize is somewhat arbitrary. */
#define MAX_BLOCKSIZE	(1024*1024)
#define DEFAULT_BLOCKSIZE	(128*1024)
static unsigned int blocksize = DEFAULT_BLOCKSIZE;
static char *buf = NULL;

static unsigned char digest[DIGEST_LEN_MAX] = { 0, };

static int run_dedupe = 0;

struct filerec {
	int		fd;
	const char	*filename;

	struct list_head	block_list;
	struct list_head	extent_list;
};

static void debug_print_block(struct file_block *e, struct filerec *files)
{
	printf("%s\tloff: %llu lblock: %llu\n", files[e->b_file].filename,
	       (unsigned long long)e->b_loff,
	       (unsigned long long)e->b_loff / blocksize);
}

static void debug_print_tree(struct hash_tree *tree, struct filerec *files,
			     int numfiles)
{
	struct rb_root *root = &tree->root;
	struct rb_node *node = rb_first(root);
	struct dupe_blocks_list *dups;
	struct file_block *block;
	struct list_head *p;

	if (!debug)
		return;

	dprintf("Block hash tree has %u hash nodes and %u block items\n",
		tree->num_hashes, tree->num_blocks);

	while (1) {
		if (node == NULL)
			break;

		dups = rb_entry(node, struct dupe_blocks_list, dl_node);

		dprintf("All blocks with hash: ");
		debug_print_digest(stdout, dups->dl_hash);
		dprintf("\n");

		list_for_each(p, &dups->dl_list) {
			block = list_entry(p, struct file_block, b_list);
			debug_print_block(block, files);
		}
		node = rb_next(node);
	}
}

static void print_results(struct results_tree *res, struct filerec *files,
			  int numfiles)
{
	struct rb_root *root = &res->root;
	struct rb_node *node = rb_first(root);
	struct dupe_extents *dext;
	struct extent *extent;

	printf("Found %u instances of duplicated extents\n", res->num_dupes);

	while (1) {
		uint64_t len, len_blocks;

		if (node == NULL)
			break;

		dext = rb_entry(node, struct dupe_extents, de_node);

		len = dext->de_len;
		len_blocks = len / blocksize;

		printf("%u extents had length %llu (%llu) for a score of %llu.\n",
		       dext->de_num_dupes, (unsigned long long)len_blocks,
		       (unsigned long long)len,
		       (unsigned long long)dext->de_score);
		if (verbose) {
			printf("Hash is: ");
			debug_print_digest(stdout, dext->de_hash);
			printf("\n");
		}
		list_for_each_entry(extent, &dext->de_extents, e_list) {
			printf("%s\tstart block: %llu (%llu)\n",
			       files[extent->e_file].filename,
			       (unsigned long long)extent->e_loff / blocksize,
			       (unsigned long long)extent->e_loff);
		}

		node = rb_next(node);
	}
}

static void dedupe_results(struct results_tree *res, struct filerec *files,
			   int numfiles)
{
	int ret, i;
	struct rb_root *root = &res->root;
	struct rb_node *node = rb_first(root);
	struct dupe_extents *dext;
	struct extent *extent;
	struct dedupe_ctxt *ctxt = NULL;

	printf("Found %u instances of duplicated extents\n", res->num_dupes);

	while (1) {
		uint64_t len, len_blocks;

		if (node == NULL)
			break;

		dext = rb_entry(node, struct dupe_extents, de_node);

		len = dext->de_len;
		len_blocks = len / blocksize;

		printf("%u extents had length %llu (%llu) for a score of %llu.\n",
		       dext->de_num_dupes, (unsigned long long)len_blocks,
		       (unsigned long long)len,
		       (unsigned long long)dext->de_score);
		if (verbose) {
			printf("Hash is: ");
			debug_print_digest(stdout, dext->de_hash);
			printf("\n");
		}
		list_for_each_entry(extent, &dext->de_extents, e_list) {
			printf("%s\tstart block: %llu (%llu)\n",
			       files[extent->e_file].filename,
			       (unsigned long long)extent->e_loff / blocksize,
			       (unsigned long long)extent->e_loff);

			if (ctxt == NULL) {
				ctxt = new_dedupe_ctxt(res->num_dupes - 1,
						       extent->e_loff, len,
						       files[extent->e_file].fd,
						       extent->e_file);
				abort_on(ctxt == NULL);
			} else {
				add_extent_to_dedupe(ctxt, extent->e_loff, len,
						     files[extent->e_file].fd,
						     extent->e_file);
			}
		}

		printf("Running dedupe...\n");

		ret = dedupe_extents(ctxt);
		if (ret) {
			ret = errno;
			fprintf(stderr,
				"FAILURE: Dedupe ioctl returns %d: %s\n",
				ret, strerror(ret));
			goto next;
		}

		printf("Dedupe from: \"%s\"\toffset: %llu\tlen: %llu\n",
		       files[ctxt->ioctl_fd_index].filename,
		       (unsigned long long)ctxt->ioctl_fd_off,
		       (unsigned long long)ctxt->len);

		for (i = 0; i < num_dedupe_requests(ctxt); i++) {
			uint64_t target_loff, target_bytes;
			int status;
			unsigned int filerec_index;

			get_dedupe_result(ctxt, i, &status, &target_loff,
					  &target_bytes, &filerec_index);

			printf("\"%s\":\toffset: %llu\tdeduped bytes: %llu"
			       "\tstatus: %d\n", files[filerec_index].filename,
			       (unsigned long long)target_loff,
			       (unsigned long long)target_bytes, status);
		}

next:
		free_dedupe_ctxt(ctxt);
		ctxt = NULL;

		node = rb_next(node);
	}

	free_dedupe_ctxt(ctxt);
}

static int csum_whole_file(struct hash_tree *tree, struct filerec *file,
			   int index)
{
	int ret, expecting_eof = 0;
	ssize_t bytes;
	uint64_t off;
	struct file_block *prev = NULL;

	vprintf("csum: %s\n", file->filename);

	ret = off = 0;

	while (1) {
		bytes = read(file->fd, buf, blocksize);
		if (bytes < 0) {
			ret = errno;
			fprintf(stderr, "Unable to read file %s: %s\n",
				file->filename, strerror(ret));
			break;
		}

		if (bytes == 0)
			break;

		/*
		 * TODO: This should be a graceful exit or we replace
		 * the read call above with a wrapper which retries
		 * until an eof.
		 */
		abort_on(expecting_eof);

		if (bytes < blocksize) {
			expecting_eof = 1;
			continue;
		}

		/* Is this necessary? */
		memset(digest, 0, DIGEST_LEN_MAX);

		checksum_block(buf, bytes, digest);

		prev = insert_hashed_block(tree, digest, index, off,
					   &file->block_list);
		if (prev == NULL) {
			ret = ENOMEM;
			break;
		}

		off += bytes;
	}

	return ret;
}

static int populate_hash_tree(struct hash_tree *tree,
			      struct filerec *files, int numfiles)
{
	int i, ret = -1;

	for(i = 0; i < numfiles; i++) {
		ret = csum_whole_file(tree, &files[i], i);
		if (ret)
			break;
	}

	return ret;
}

static void usage(const char *prog)
{
	printf("duperemove %s\n", VERSTRING);
	printf("Find duplicate extents and print them to stdout\n\n");
	printf("Usage: %s [-v] [-d] [-h] [-b blocksize-in-K] OBJECTS\n", prog);
	printf("Where \"OBJECTS\" is a list of files (or directories) which\n");
	printf("we want to find duplicate extents in. If a directory is \n");
	printf("specified, all regular files inside of it will be scanned.\n");
	printf("\n\t<switches>\n");
	printf("\t-b bsize\tUse bsize blocks - specify in kilobytes. Default is %d.\n", DEFAULT_BLOCKSIZE / 1024);
	printf("\t-v\t\tBe verbose.\n");
	printf("\t-d\t\tPrint debug messages, forces -v if selected.\n");
	printf("\t-h\t\tPrints this help text.\n");
}

/*
 * Ok this is doing more than just parsing options.
 */
static int parse_options(int argc, char **argv, struct filerec **files,
			 int *numfiles)
{
	int i, c;
	struct filerec *f;

	if (argc < 2)
		return 1;

	while ((c = getopt(argc, argv, "b:vdDh?")) != -1) {
		switch (c) {
		case 'b':
			blocksize = atoi(optarg);
			blocksize *= 1024;
			if (blocksize < MIN_BLOCKSIZE ||
			    blocksize > MAX_BLOCKSIZE)
				return EINVAL;
			break;
		case 'D':
			run_dedupe = 1;
			break;
		case 'd':
			debug = 1;
			/* Fall through */
		case 'v':
			verbose = 1;
			break;
		case 'h':
		case '?':
		default:
			return 1;
		}
	}

	*numfiles = argc - optind;

	f = calloc(*numfiles, sizeof(struct filerec));
	if (f == NULL)
		return ENOMEM;

	for (i = 0; i < *numfiles; i++) {
		int fd;
		const char *name = argv[i + optind];

		fd = open(name, O_RDONLY);
		if (fd == -1) {
			fprintf(stderr, "Could not open \"%s\"\n", name);
			return errno;
		}

		f[i].fd = fd;
		f[i].filename = name;
		INIT_LIST_HEAD(&f[i].block_list);
		INIT_LIST_HEAD(&f[i].extent_list);
	}

	*files = f;

	return 0;
}

static void record_match(struct results_tree *res, unsigned char *digest,
			 struct filerec *orig, struct filerec *walk,
			 struct file_block **start, struct file_block **end)
{
	int ret;
	int fileids[2];
	uint64_t soff[2], eoff[2];
	struct list_head *list[2] = { &orig->extent_list, &walk->extent_list };
	uint64_t len;

	fileids[0] = start[0]->b_file;
	fileids[1] = start[1]->b_file;

	soff[0] = start[0]->b_loff;
	soff[1] = start[1]->b_loff;

	eoff[0] = blocksize + end[0]->b_loff;
	eoff[1] = blocksize + end[1]->b_loff;

	len = eoff[0] - soff[0];

	ret = insert_result(res, digest, fileids, soff, eoff, list);
	abort_on(ret != 0);

	dprintf("Duplicated extent of %llu blocks in files:\n%s\t\t%s\n",
		(unsigned long long)len / blocksize, orig->filename,
		walk->filename);

	dprintf("%llu-%llu\t\t%llu-%llu\n",
		(unsigned long long)soff[0] / blocksize,
		(unsigned long long)eoff[0] / blocksize,
		(unsigned long long)soff[1] / blocksize,
		(unsigned long long)eoff[1] / blocksize);
}

struct dupe_walk_ctxt {
	struct file_block	*orig;

	struct filerec		*orig_file;
	struct filerec		*walk_file;

	struct results_tree	*res;
};

static int walk_dupe_block(struct file_block *block, void *priv)
{
	struct dupe_walk_ctxt *ctxt = priv;
	struct file_block *orig = ctxt->orig;
	struct file_block *start[2] = { orig, block };
	struct file_block *end[2];
	struct running_checksum *csum;
	unsigned char match_id[DIGEST_LEN_MAX] = {0, };

	if (block_seen(block))
		goto out;

	csum = start_running_checksum();

	abort_on(block->b_parent != orig->b_parent);

	while (block->b_parent == orig->b_parent) {
		mark_block_seen(block);
		mark_block_seen(orig);

		end[0] = orig;
		end[1] = block;

		add_to_running_checksum(csum, digest_len,
					block->b_parent->dl_hash);

		/*
		 * This is kind of ugly, however it does correctly
		 * signify the end of our list.
		 */
		if (orig->b_file_next.next == &ctxt->orig_file->block_list ||
		    block->b_file_next.next == &ctxt->walk_file->block_list)
			break;

		orig =	list_entry(orig->b_file_next.next, struct file_block,
				   b_file_next);
		block =	list_entry(block->b_file_next.next, struct file_block,
				   b_file_next);
	}

	finish_running_checksum(csum, match_id);

	record_match(ctxt->res, match_id, ctxt->orig_file, ctxt->walk_file,
		     start, end);
out:
	return 0;
}

static void find_file_dupes(struct filerec *file, struct filerec *walk_file,
			    unsigned int walk_file_index,
			    struct results_tree *res)
{
	struct file_block *cur;
	struct dupe_walk_ctxt ctxt = { 0, };

	list_for_each_entry(cur, &file->block_list, b_file_next) {
		if (block_seen(cur))
			continue;
		/*
		 * For each file block with the same hash:
		 *  - Traverse, along with original file until we have no match
		 *     - record
		 */
		memset(&ctxt, 0, sizeof(struct dupe_walk_ctxt));
		ctxt.orig_file = file;
		ctxt.walk_file = walk_file;
		ctxt.orig = cur;
		ctxt.res = res;
		for_each_dupe(cur, walk_file_index, walk_dupe_block, &ctxt);
	}
	clear_all_seen_blocks();
}

int main(int argc, char **argv)
{
	int i, j, ret = 0;
	struct hash_tree tree;
	struct results_tree res;
	struct filerec *files = NULL;
	int numfiles;

	if (init_hash())
		return ENOMEM;

	init_hash_tree(&tree);
	init_results_tree(&res);

	if (parse_options(argc, argv, &files, &numfiles)) {
		usage(argv[0]);
		return EINVAL;
	}

	vprintf("Using %uK blocks\n", blocksize/1024);

	buf = malloc(blocksize);
	if (!buf)
		return ENOMEM;

	ret = populate_hash_tree(&tree, files, numfiles);
	if (ret) {
		fprintf(stderr, "Error while populating extent tree!\n");
		goto out;
	}

	debug_print_tree(&tree, files, numfiles);

	for (i = 0; i < numfiles; i++) {
		for (j = i; j < numfiles; j++) {
			if (i == j)
				continue;

			find_file_dupes(&files[i], &files[j], j, &res);
		}
	}

	if (debug) {
		print_results(&res, files, numfiles);
		printf("\n\nRemoving overlapping extents\n\n");
	}

	for (i = 0; i < numfiles; i++)
		remove_overlapping_extents(&res, &files[i].extent_list);

	if (run_dedupe)
		dedupe_results(&res, files, numfiles);
	else
		print_results(&res, files, numfiles);

out:
	return ret;
}
