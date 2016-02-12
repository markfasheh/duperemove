/*
 * debug.h
 *
 * Copyright (C) 2016 SUSE.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 */

#ifndef	__DEBUG_H__
#define	__DEBUG_H__

#include <stdio.h>
#include <stdbool.h>

extern int verbose;
extern int debug;

#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)

#define dprintf(args...)	if (debug) printf(args)
#define vprintf(args...)	if (verbose) printf(args)
void print_stack_trace(void);/* defined in util.c */
#define	abort_lineno()	do {						\
		printf("ERROR: %s:%d\n", __FILE__, __LINE__);		\
		print_stack_trace();					\
		abort();						\
	} while (0)

#define abort_on(condition) do {					\
		if (unlikely(condition)) {				\
			printf("ERROR: %s:%d\n", __FILE__, __LINE__);	\
			print_stack_trace();				\
			abort();					\
		}							\
	} while(0)


/*
 * compiletime_assert and associated code taken from
 * linux-3.14.git/include/linux/compiler.h
 */

# define __compiletime_warning(message)
# define __compiletime_error(message)

/*
 * Sparse complains of variable sized arrays due to the temporary variable in
 * __compiletime_assert. Unfortunately we can't just expand it out to make
 * sparse see a constant array size without breaking compiletime_assert on old
 * versions of GCC (e.g. 4.2.4), so hide the array from sparse altogether.
 */
#define __compiletime_error_fallback(condition) \
	do { ((void)sizeof(char[1 - 2 * condition])); } while (0)

#define __compiletime_assert(condition, msg, prefix, suffix)		\
	do {								\
		bool __cond = !(condition);				\
		extern void prefix ## suffix(void) __compiletime_error(msg); \
		if (__cond)						\
			prefix ## suffix();				\
		__compiletime_error_fallback(__cond);			\
	} while (0)

/**
 * compiletime_assert - break build and emit msg if condition is false
 * @condition: a compile-time constant condition to check
 * @msg:       a message to emit if condition is false
 *
 * In tradition of POSIX assert, this macro will break the build if the
 * supplied condition is *false*, emitting the supplied error message if the
 * compiler has support to do so.
 */
#define compiletime_assert(condition, msg) \
	__compiletime_assert(condition, msg, __compiletime_assert_, __LINE__)

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
