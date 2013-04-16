#ifndef __RESULTS_TREE_
#define __RESULTS_TREE_

struct results_tree {
	struct rb_root	root;
	unsigned int	num_dupes;
};

struct dupe_extents {
	unsigned int	de_num_dupes;
	uint64_t	de_len;
	unsigned char		de_hash[DIGEST_LEN_MAX];

	uint64_t	de_score;

	struct list_head	de_extents;

	struct rb_node		de_node;
};

struct extent	{
	struct dupe_extents	*e_parent;

	uint64_t	e_loff;
	unsigned int	e_file;

	struct list_head	e_list; /* For de_extents */

	/* Each file keeps a list of it's own dupes. This makes it
	 * easier to remove overlapping duplicates. */
	struct list_head	e_file_extents;
};

/* endoff is NOT inclusive! */
int insert_result(struct results_tree *res, unsigned char *digest,
		  int fileids[2], uint64_t startoff[2], uint64_t endoff[2],
		  struct list_head *head[2]);

void remove_overlapping_extents(struct results_tree *res,
				struct list_head *head);

void init_results_tree(struct results_tree *res);

#endif /* __RESULTS_TREE__ */
