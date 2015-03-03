#ifndef __DTREE__
#define __DTREE__

#include <stdint.h>
#include "rbtree.h"
#include "list.h"

struct d_tree {
	unsigned char *digest;
	struct rb_node  t_node;
};

struct d_tree *digest_new(unsigned char *digest);
int digest_insert(struct rb_root *root, struct d_tree *token);
struct d_tree *digest_find(struct rb_root *root,
				unsigned char *digest);

uint64_t digest_count(struct rb_root *root);

#endif /* __DTREE__ */
