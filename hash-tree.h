#ifndef __HASH_TREE__
#define __HASH_TREE__

struct hash_tree {
	struct rb_root	root;
	unsigned int	num_blocks;
	unsigned int	num_hashes;
};

struct dupe_blocks_list {
	struct rb_node	dl_node;
	unsigned int	dl_num_elem;
	struct list_head	dl_list;

	unsigned char		dl_hash[DIGEST_LEN_MAX];
};

struct file_block {
	struct dupe_blocks_list	*b_parent;
	struct filerec	*b_file;
	unsigned int	b_seen;
	uint64_t	b_loff;

	struct list_head	b_list;  /* For d_list, all blocks
					  * with this md5. */

	struct list_head	b_file_next; /* Points to the next logical
					      * extent for this file. */
};

int insert_hashed_block(struct hash_tree *tree, unsigned char *digest,
			struct filerec *file, uint64_t loff);

typedef int (for_each_dupe_t)(struct file_block *, void *);
void for_each_dupe(struct file_block *block, struct filerec *file,
		   for_each_dupe_t func, void *priv);

int block_seen(struct file_block *block);
void mark_block_seen(struct file_block *block);
void clear_all_seen_blocks(void);

void init_hash_tree(struct hash_tree *tree);

#endif /* __HASH_TREE__ */
