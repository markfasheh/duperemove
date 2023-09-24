#ifndef	__RUN_DEDUPE_H__
#define	__RUN_DEDUPE_H__

#include <stdbool.h>
#include "opt.h"

void print_dupes_table(struct results_tree *res, bool whole_file);
void dedupe_results(struct results_tree *res, bool whole_file);

int fdupes_dedupe(void);

#endif	/* __RUN_DEDUPE_H__ */
