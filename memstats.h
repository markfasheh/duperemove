/*
 * memstats.h
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

#ifndef	__MEMSTATS_H__
#define	__MEMSTATS_H__

#include "glib.h"

/*
 * Rudimentary tracking of object allocation. Use this within a c file
 * to declare the tracking variable and the print function body.
 *
 * In addition, memstats.h needs to declare an extern and function
 * prototype (see below) and print_mem_stats() in memstats.c needs an
 * update.
 */
#ifdef	DEBUG_BUILD
#define	LOCK_MEMSTATS
#endif
static inline void increment_counters(unsigned long long *num_type,
				      unsigned long long *max_type,
				      unsigned long long count, GMutex *mutex)
{
#ifdef	LOCK_MEMSTATS
	g_mutex_lock(mutex);
#endif
	(*num_type) += count;
	if ((*num_type) > (*max_type))
		(*max_type) = *num_type;
#ifdef	LOCK_MEMSTATS
	g_mutex_unlock(mutex);
#endif
}
static inline void decrement_counters(unsigned long long *num_type,
				      GMutex *mutex)
{
#ifdef	LOCK_MEMSTATS
	g_mutex_lock(mutex);
#endif
	(*num_type)--;
#ifdef	LOCK_MEMSTATS
	g_mutex_unlock(mutex);
#endif
}

#define declare_alloc_tracking(_type)					\
GMutex	alloc_##_mutex;							\
unsigned long long num_##_type = 0;					\
unsigned long long max_##_type = 0;					\
static inline struct _type *malloc_##_type(void)			\
{									\
	struct _type *t = malloc(sizeof(struct _type));			\
	if (t)								\
		increment_counters(&num_##_type, &max_##_type, 1ULL,	\
				   &alloc_##_mutex);			\
	return t;							\
}									\
static inline struct _type *calloc_##_type(int n)			\
{									\
	struct _type *t = calloc(n, sizeof(struct _type));		\
	if (t)								\
		increment_counters(&num_##_type, &max_##_type, n,	\
				   &alloc_##_mutex);			\
	return t;							\
}									\
static inline void free_##_type(struct _type *t)			\
{									\
	if (t) {							\
		decrement_counters(&num_##_type, &alloc_##_mutex);	\
		free(t);						\
	}								\
}									\
void show_allocs_##_type(void)						\
{									\
	long size = sizeof(struct _type);				\
	unsigned long long total = size * num_##_type;			\
	unsigned long long max_total = size * max_##_type;		\
	printf("struct " #_type " num: %llu sizeof: %lu total: %llu "	\
	       "max: %llu max total: %llu\n",				\
	       num_##_type, size, total, max_##_type, max_total);	\
}

#define declare_alloc_tracking_header(_type)				\
extern unsigned long long num_##_type;					\
extern unsigned long long max_##_type;					\
void show_allocs_##_type(void);

declare_alloc_tracking_header(file_block);
declare_alloc_tracking_header(dupe_blocks_list);
declare_alloc_tracking_header(dupe_extents);
declare_alloc_tracking_header(extent);
declare_alloc_tracking_header(extent_dedupe_info);
declare_alloc_tracking_header(filerec);
declare_alloc_tracking_header(filerec_token);
declare_alloc_tracking_header(file_hash_head);
declare_alloc_tracking_header(find_dupes_cmp);
/* Can be called anywhere we want to dump the above statistics */
void print_mem_stats(void);

static inline void *malloc_count(size_t size, unsigned long long *num_type,
				 unsigned long long *max_type)
{
	void *obj = malloc(size);
	if (obj) {
		(*num_type)++;
		if (num_type > max_type)
			*max_type = *num_type;
	}

	return obj;
}
static inline void *calloc_count(size_t size, unsigned long long *num_type)
{
	void *obj = malloc(size);
	if (obj)
		(*num_type)++;
	return obj;
}

#endif	/* __MEMSTATS_H__ */
