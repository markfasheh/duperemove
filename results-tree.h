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
	struct rb_root		de_extents_root;

	struct rb_node		de_node;
};

struct extent	{
	struct dupe_extents	*e_parent;

	uint64_t	e_loff;
	struct filerec	*e_file;

	struct list_head	e_list; /* For de_extents */
	struct rb_node		e_node; /* For de_extents_root */

	/* Each file keeps a list of it's own dupes. This makes it
	 * easier to remove overlapping duplicates. */
	struct list_head	e_file_extents; /* filerec->extent_list */

	uint64_t		e_poff;
};

/* endoff is NOT inclusive! */
int insert_result(struct results_tree *res, unsigned char *digest,
		  struct filerec *recs[2], uint64_t startoff[2],
		  uint64_t endoff[2]);

void remove_overlapping_extents(struct results_tree *res, struct filerec *file);

void init_results_tree(struct results_tree *res);
void dupe_extents_free(struct dupe_extents *dext, struct results_tree *res);

#endif /* __RESULTS_TREE__ */
