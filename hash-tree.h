#ifndef __HASH_TREE__
#define __HASH_TREE__

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

	/*
	 * num_files and files_root are used when the total number of
	 * blocks in the list exceeds DUPLIST_CONVERT_LIMIT (defined
	 * below)
	 */
	unsigned int		dl_num_files;
	struct rb_root		dl_files_root;
	struct list_head	dl_large_list; /* Temporary list for
						* use by extent finding code */

	unsigned char		dl_hash[DIGEST_LEN_MAX];
};

/* Max number of blocks before we'll add filerec tokens */
#define	DUPLIST_CONVERT_LIMIT		30000

/* Fiemap flags that would cause us to skip comparison of the block */
#define FIEMAP_SKIP_FLAGS	(FIEMAP_EXTENT_UNKNOWN|FIEMAP_EXTENT_DATA_INLINE|FIEMAP_EXTENT_UNWRITTEN)
/* Fiemap flags that indicate the extent may have already been deduped */
#define FIEMAP_DEDUPED_FLAGS	(FIEMAP_EXTENT_SHARED)

#define FILE_BLOCK_SKIP_COMPARE	0x0001
#define FILE_BLOCK_DEDUPED	0x0002
#define FILE_BLOCK_HOLE		0x0004

struct file_block {
	struct dupe_blocks_list	*b_parent;
	struct filerec	*b_file;
	unsigned int	b_seen;
	uint64_t	b_loff;
	unsigned int	b_flags;

	struct list_head	b_list;  /* For dl_list, all blocks
					  * with this md5. */

	struct list_head	b_file_next; /* filerec->block_list */
};

int insert_hashed_block(struct hash_tree *tree, unsigned char *digest,
			struct filerec *file, uint64_t loff, unsigned int flags);
void remove_hashed_blocks(struct hash_tree *tree, struct filerec *file);

typedef int (for_each_dupe_t)(struct file_block *, void *);
void for_each_dupe(struct file_block *block, struct filerec *file,
		   for_each_dupe_t func, void *priv);

int block_seen(struct file_block *block);
int block_ever_seen(struct file_block *block);
void mark_block_seen(struct file_block *block);
void clear_all_seen_blocks(void);

void init_hash_tree(struct hash_tree *tree);

#endif /* __HASH_TREE__ */
