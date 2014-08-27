#ifndef	__DEBUG_H__
#define	__DEBUG_H__

#include <stdio.h>

extern int verbose;
extern int debug;

/*
 * Rudimentary tracking of object allocation. Use this within a c file
 * to declare the tracking variable and the print function body.
 *
 * In addition, debug.h needs to declare an extern and function
 * prototype (see below) and print_mem_stats() in util.c needs an
 * update.
 */
#define declare_alloc_tracking(_type)					\
extern long long num_##_type;						\
static inline struct _type *malloc_##_type(void)			\
{									\
	struct _type *t = malloc(sizeof(struct _type));			\
	if (t)								\
		num_##_type++;						\
	return t;							\
}									\
static inline struct _type *calloc_##_type(int n)			\
{									\
	struct _type *t = calloc(n, sizeof(struct _type));		\
	if (t)								\
		num_##_type += n;					\
	return t;							\
}									\
static inline void free_##_type(struct _type *t)			\
{									\
	if (t) {							\
		num_##_type--;						\
		free(t);						\
	}								\
}									\
void show_allocs_##_type(void)						\
{									\
	long size = sizeof(struct _type);				\
	unsigned long long total = size * num_##_type;			\
	printf("struct " #_type " num: %llu sizeof: %lu total: %llu\n", \
	       num_##_type, size, total);				\
}

#define declare_alloc_tracking_header(_type)				\
long long num_##_type;							\
void show_allocs_##_type(void);

declare_alloc_tracking_header(file_block);
declare_alloc_tracking_header(dupe_blocks_list);
declare_alloc_tracking_header(dupe_extents);
declare_alloc_tracking_header(extent);
declare_alloc_tracking_header(filerec);
/* Can be called anywhere we want to dump the above statistics */
void print_mem_stats(void);

#define dprintf(args...)	if (debug) printf(args)
#define vprintf(args...)	if (verbose) printf(args)
#define	abort_lineno()	do {						\
		printf("ERROR: %s:%d\n", __FILE__, __LINE__);		\
		abort();						\
	} while (0)

#define abort_on(condition) do {					\
		if (condition) {					\
			printf("ERROR: %s:%d\n", __FILE__, __LINE__);\
			abort();					\
		}							\
	} while(0)

/*
 * BUILD_BUG_ON() and associated code taken from
 * linux-2.6.git/include/linux/bug.h
 */

/**
 * BUILD_BUG_ON_MSG - break compile if a condition is true & emit supplied
 *		      error message.
 * @condition: the condition which the compiler should know is false.
 *
 * See BUILD_BUG_ON for description.
 */
#define BUILD_BUG_ON_MSG(cond, msg) compiletime_assert(!(cond), msg)

/**
 * BUILD_BUG_ON - break compile if a condition is true.
 * @condition: the condition which the compiler should know is false.
 *
 * If you have some code which relies on certain constants being equal, or
 * some other compile-time-evaluated condition, you should use BUILD_BUG_ON to
 * detect if someone changes it.
 *
 * The implementation uses gcc's reluctance to create a negative array, but gcc
 * (as of 4.4) only emits that error for obvious cases (e.g. not arguments to
 * inline functions).  Luckily, in 4.3 they added the "error" function
 * attribute just for this type of case.  Thus, we use a negative sized array
 * (should always create an error on gcc versions older than 4.4) and then call
 * an undefined function with the error attribute (should always create an
 * error on gcc 4.3 and later).  If for some reason, neither creates a
 * compile-time error, we'll still have a link-time error, which is harder to
 * track down.
 */
#ifndef __OPTIMIZE__
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#else
#define BUILD_BUG_ON(condition) \
	BUILD_BUG_ON_MSG(condition, "BUILD_BUG_ON failed: " #condition)
#endif

#endif	/* __DEBUG_H__ */
