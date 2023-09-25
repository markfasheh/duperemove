/*
 * util.h
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
 * Authors: Mark Fasheh <mfasheh@suse.de>
 */

#ifndef	__UTIL_H__
#define	__UTIL_H__

#include <stdlib.h>
#include <dirent.h>
#include <stdint.h>
#include <sys/time.h>
#include <unistd.h>

/* controlled by user options, turns pretty print on if true. */
extern int human_readable;

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/*
 * Code for parsing and printing human readable numbers is taken from
 * btrfs-progs/util.c and modified locally to suit my purposes.
 */
uint64_t parse_size(char *s);
int pretty_size_snprintf(uint64_t size, char *str, size_t str_bytes);
#define pretty_size(size) 						\
	({								\
		static __thread char _str[32];				\
		(void)pretty_size_snprintf((size), _str, sizeof(_str));	\
		_str;							\
	})

/* Trivial wrapper around gettimeofday */
struct elapsed_time {
	struct timeval	start;
	struct timeval	end;
	const char	*name;
	double		elapsed;
};
void record_start(struct elapsed_time *e, const char *name);
void record_end_print(struct elapsed_time *e);

int num_digits(unsigned long long num);

void get_num_cpus(unsigned int *nr_phys, unsigned int *nr_log);

/* Bump up maximum open file limit. */
int increase_limits(void);

#define _cleanup_(x) __attribute__((cleanup(x)))
static inline void freep(void *p)
{
	free(*(void**) p);
}

static inline void closedirectory(DIR **p)
{
	if (*p)
		closedir(*p);
}

static inline void closefd(int *fd)
{
	if (*fd >= 0)
		close(*fd);
}

#endif	/* __UTIL_H__ */
