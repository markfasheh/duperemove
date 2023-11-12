/*
 * threads.h
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

#ifndef	__THREADS_H__
#define	__THREADS_H__

#include <stdlib.h>
#include <stdio.h>

#include "opt.h"
#include "glib.h"

struct threads_cleanup_item {
	void (*function)(void *ptr);
	void *ptr;
};

struct threads_pool {
	GThreadPool *pool;
	struct threads_cleanup_item** items;
	unsigned int item_count;
	GMutex mutex; /* Protect the cleanup items operations */
};

void setup_pool(struct threads_pool *pool, void *function, void *arg);
void register_cleanup(struct threads_pool *pool, void *function, void *ptr);
void free_pool(struct threads_pool *pool);
#endif	/* __THREADS_H__ */
