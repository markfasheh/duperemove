#ifndef	__RUN_DEDUPE_H__
#define	__RUN_DEDUPE_H__

/* from duperemove.c */
extern unsigned int blocksize;
extern int target_rw;
extern unsigned int io_threads;

void print_dupes_table(struct results_tree *res);
void dedupe_results(struct results_tree *res, struct hash_tree *hashes);

int fdupes_dedupe(void);

#endif	/* __RUN_DEDUPE_H__ */
