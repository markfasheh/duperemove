#ifndef __DTREE__
#define __DTREE__

#include <stdint.h>
#include "rbtree.h"
#include "list.h"

struct d_tree {
	unsigned char *digest;
	struct rb_node  t_node;
};

/* alloc and insert a new digest into the tree */
int digest_insert(struct rb_root *root, unsigned char *digest);
struct d_tree *digest_find(struct rb_root *root,
			   unsigned char *digest);

uint64_t digest_count(struct rb_root *root);
void digest_free(struct rb_root *root);
void debug_print_digest_tree(struct rb_root *d_tree);

#endif /* __DTREE__ */
