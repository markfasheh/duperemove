#include <stdlib.h>
#include <stddef.h>

#include "interval_tree.h"
#include "interval_tree_generic.h"

#define START(node) ((node)->start)
#define LAST(node)  ((node)->last)

INTERVAL_TREE_DEFINE(struct interval_tree_node, rb,
		     uint64_t, __subtree_last,
		     START, LAST,, interval_tree)
