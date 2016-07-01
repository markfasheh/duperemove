#ifndef _LINUX_INTERVAL_TREE_H
#define _LINUX_INTERVAL_TREE_H

#include <stdint.h>
#include "rbtree.h"

struct interval_tree_node {
	struct rb_node rb;
	uint64_t start;	/* Start of interval */
	uint64_t last;	/* Last location _in_ interval */
	uint64_t __subtree_last;
};

extern void
interval_tree_insert(struct interval_tree_node *node, struct rb_root *root);

extern void
interval_tree_remove(struct interval_tree_node *node, struct rb_root *root);

extern struct interval_tree_node *
interval_tree_iter_first(struct rb_root *root,
			 uint64_t start, uint64_t last);

extern struct interval_tree_node *
interval_tree_iter_next(struct interval_tree_node *node,
			uint64_t start, uint64_t last);

#endif	/* _LINUX_INTERVAL_TREE_H */
