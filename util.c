/*
 * util.c
 *
 * Copyright (C) 2014 SUSE except where noted.  All rights reserved.
 *
 * Code taken from btrfs-progs/util.c is:
 * Copyright (C) 2007 Oracle.  All rights reserved.
 * Copyright (C) 2008 Morey Roof.  All rights reserved.

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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <inttypes.h>
#include <execinfo.h>
#include <sys/time.h>

#include "debug.h"
#include "util.h"

int human_readable = 0;

uint64_t parse_size(char *s)
{
	int i;
	char c;
	uint64_t mult = 1;

	for (i = 0; s && s[i] && isdigit(s[i]); i++) ;
	if (!i) {
		fprintf(stderr, "ERROR: size value is empty\n");
		exit(50);
	}

	if (s[i]) {
		c = tolower(s[i]);
		switch (c) {
		case 'e':
			mult *= 1024;
			/* fallthrough */
		case 'p':
			mult *= 1024;
			/* fallthrough */
		case 't':
			mult *= 1024;
			/* fallthrough */
		case 'g':
		case 'G':
			mult *= 1024;
			/* fallthrough */
		case 'm':
		case 'M':
			mult *= 1024;
			/* fallthrough */
		case 'k':
		case 'K':
			mult *= 1024;
			/* fallthrough */
		case 'b':
			break;
		default:
			fprintf(stderr, "ERROR: Unknown size descriptor "
				"'%c'\n", c);
			exit(1);
		}
	}
	if (s[i] && s[i+1]) {
		fprintf(stderr, "ERROR: Illegal suffix contains "
			"character '%c' in wrong position\n",
			s[i+1]);
		exit(51);
	}
	return strtoull(s, NULL, 10) * mult;
}

static char *size_strs[] = { "", "K", "M", "G", "T", "P", "E"};
int pretty_size_snprintf(uint64_t size, char *str, size_t str_bytes)
{
	uint32_t num_divs = 0;
	float fraction;

	if (str_bytes == 0)
		return 0;

	if (!human_readable)
		return snprintf(str, str_bytes, "%"PRIu64, size);

	if (size < 1024){
		fraction = size;
		num_divs = 0;
	} else {
		uint64_t last_size = size;
		num_divs = 0;
		while(size >= 1024){
			last_size = size;
			size /= 1024;
			num_divs ++;
		}

		if (num_divs >= ARRAY_SIZE(size_strs)) {
			str[0] = '\0';
			return -1;
		}
		fraction = (float)last_size / 1024;
	}
	return snprintf(str, str_bytes, "%.1f%s", fraction,
			size_strs[num_divs]);
}

void print_stack_trace(void)
{
	void *trace[16];
	char **messages = (char **)NULL;
	int i, trace_size = 0;

	trace_size = backtrace(trace, 16);
	messages = backtrace_symbols(trace, trace_size);
	printf("[stack trace follows]\n");
	for (i=0; i < trace_size; i++)
		printf("%s\n", messages[i]);
	free(messages);
}

void record_start(struct elapsed_time *e, const char *name)
{
	e->name = name;
	gettimeofday(&e->start, NULL);
}

static void record_end(struct elapsed_time *e)
{
	gettimeofday(&e->end, NULL);

	e->elapsed = (e->end.tv_sec - e->start.tv_sec) +
		((e->end.tv_usec - e->start.tv_usec) / 1000000.0F);
}

void record_end_print(struct elapsed_time *e)
{
	record_end(e);
	printf("%s took %fs\n", e->name, e->elapsed);
}
