#ifndef	__RUN_DEDUPE_H__
#define	__RUN_DEDUPE_H__

/* from duperemove.c */
extern unsigned int blocksize;
extern int target_rw;

void print_dupes_table(struct results_tree *res);
void dedupe_results(struct results_tree *res);

#endif	/* __RUN_DEDUPE_H__ */
