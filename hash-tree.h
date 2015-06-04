#ifndef __HASH_TREE__
#define __HASH_TREE__
extern unsigned int blocksize;

struct hash_tree {
	struct rb_root	root;
	uint64_t	num_blocks;
	uint64_t	num_hashes;
};

struct dupe_blocks_list {
	struct rb_node	dl_node; /* sorted by hash */
	struct rb_node	dl_by_size; /* hashstats re-sorts by dl_num_elem */

	unsigned int	dl_num_elem;
	struct list_head	dl_list;

	unsigned int		dl_num_files;
	struct rb_root		dl_files_root; /* stores file_hash_head nodes */

	unsigned char		dl_hash[DIGEST_LEN_MAX];
};

/* Fiemap flags that would cause us to skip comparison of the block */
#define FIEMAP_SKIP_FLAGS	(FIEMAP_EXTENT_DATA_INLINE|FIEMAP_EXTENT_UNWRITTEN)
/* Fiemap flags that indicate the extent may have already been deduped */
#define FIEMAP_DEDUPED_FLAGS	(FIEMAP_EXTENT_SHARED)

#define FILE_BLOCK_SKIP_COMPARE	0x0001
#define FILE_BLOCK_DEDUPED	0x0002
#define FILE_BLOCK_HOLE		0x0004
#define	FILE_BLOCK_PARTIAL	0x0008

struct file_block {
	struct dupe_blocks_list	*b_parent;
	struct filerec	*b_file;
	unsigned int	b_seen;
	uint64_t	b_loff;
	unsigned int	b_flags;

	struct list_head	b_list;  /* For dl_list, all blocks
					  * with this md5. */

	struct rb_node		b_file_next; /* filerec->block_tree */
	struct list_head	b_head_list; /* file_hash_head->h_blocks */
};

static inline unsigned long block_len(struct file_block *block)
{
	/*
	 * Avoid storing the length of each block and instead use a
	 * flag for partial blocks.
	 *
	 * NOTE: This only works if we assume that partial blocks are
	 * at the end of a file
	 */
	if (block->b_flags & FILE_BLOCK_PARTIAL)
		return block->b_file->size % blocksize;
	return blocksize;
}

int insert_hashed_block(struct hash_tree *tree, unsigned char *digest,
			struct filerec *file, uint64_t loff, unsigned int flags);
void remove_hashed_blocks(struct hash_tree *tree, struct filerec *file);

/*
 * Stores a list of blocks with the same hash / filerec
 * combination. Each dupe_blocks_list keeps a tree of these (sorted by
 * file).
 *
 * This speeds up the extent search by allowing us to skip blocks that
 * don't belong to the file we are 'walking'. Blocks are inserted into
 * h_blocks in the same order they are given to insert_hashed_block()
 * (that is, in order of increasing offset).
 */
struct file_hash_head {
	struct filerec *h_file;
	struct rb_node h_node;
	struct list_head h_blocks;
};

int file_in_dups_list(struct dupe_blocks_list *dups, struct filerec *file);
struct file_hash_head *find_file_hash_head(struct dupe_blocks_list *dups,
					   struct filerec *file);

int block_seen(struct file_block *block);
int block_ever_seen(struct file_block *block);
void mark_block_seen(struct file_block *block);
void clear_all_seen_blocks(void);

void init_hash_tree(struct hash_tree *tree);


void debug_print_block(struct file_block *e);
void debug_print_hash_tree(struct hash_tree *tree);

#endif /* __HASH_TREE__ */
