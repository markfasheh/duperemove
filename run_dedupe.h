#ifndef	__RUN_DEDUPE_H__
#define	__RUN_DEDUPE_H__

/* from duperemove.c */
extern unsigned int blocksize;
extern unsigned int io_threads;

void print_dupes_table(struct results_tree *res);
void dedupe_results(struct results_tree *res);

int fdupes_dedupe(void);

#endif	/* __RUN_DEDUPE_H__ */
