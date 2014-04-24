#ifndef	__DEBUG_H__
#define	__DEBUG_H__

#include <stdio.h>

extern int verbose;
extern int debug;

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

#endif	/* __DEBUG_H__ */
