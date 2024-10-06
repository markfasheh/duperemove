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

#include "threads.h"
#include "debug.h"

void setup_pool(struct threads_pool *pool, void *function, void *arg, unsigned int max_threads)
{
	GError *err = NULL;

	pool->item_count = 0;
	pool->items = NULL;
	pool->pool = g_thread_pool_new((GFunc) function, arg, max_threads, FALSE,
					&err);
	if (err != NULL) {
		eprintf("Unable to create thread pool: %s\n", err->message);
		g_error_free(err);
		pool->pool = NULL;
	}
}

void register_cleanup(struct threads_pool *pool, void *function, void *ptr)
{
	struct threads_cleanup_item *item;
	item = calloc(1, sizeof(struct threads_cleanup_item));
	item->ptr = ptr;
	item->function = function;

	g_mutex_lock(&pool->mutex);
	pool->items = realloc(pool->items, (pool->item_count + 1) * sizeof(struct threads_cleanup_item*));
	pool->items[pool->item_count] = item;
	pool->item_count += 1;
	g_mutex_unlock(&pool->mutex);
}

void free_pool(struct threads_pool *pool)
{
	g_thread_pool_free(pool->pool, FALSE, TRUE);

	for (unsigned int i = 0; i < pool->item_count; i++) {
		struct threads_cleanup_item *item;
		item = pool->items[i];
		item->function(item->ptr);
		free(item);
	}

	if (pool->items)
		free(pool->items);

	pool->pool = NULL;
	pool->item_count = 0;
}
