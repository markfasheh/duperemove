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
#ifdef __GLIBC__
#include <execinfo.h>
#endif
#include <sys/time.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>

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

#ifdef __GLIBC__
	trace_size = backtrace(trace, 16);
	messages = backtrace_symbols(trace, trace_size);
	printf("[stack trace follows]\n");
	for (i=0; i < trace_size; i++)
		printf("%s\n", messages[i]);
	free(messages);
#endif
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

int num_digits(unsigned long long num)
{
	unsigned int digits = 0;

	while (num) {
		num /= 10;
		digits++;
	}
	return digits;
}

#define	VENDOR_KEY	"vendor_id"
#define	VENDOR_VAL	"GenuineIntel"
#define	FLAGS_KEY	"flags"
#define	HT_FLAG		"ht"
#define	CPUINFO_DELIM	':'
#define	FLAGS_DELIM	' '

/* Checks /proc/cpuinfo for an Intel CPU with hyperthreading. */
static int detect_ht(void)
{
	FILE *fp;
	int err = 0;
	int ret = 0;
	char line[LINE_MAX + 1];
	char *c, *val, *key, *flag;
	int check_vendor = 1;

	fp = fopen("/proc/cpuinfo", "r");
	if (fp == NULL) {
		err = errno;
		goto out;
	}

	while (fgets(line, LINE_MAX + 1, fp) != NULL) {
		c = strchr(line, CPUINFO_DELIM);
		if (!c)
			continue;
		key = line;
		val = c + 1;/* line is \0 delimited so this should be safe */

		if (*val == '\0') /* No value... */
			continue;

		/* Strip trailing whitespace from the key. */
		do {
			*c = '\0';
			c--;
		} while (c > key && !isalnum(*c));

		/* Strip leading and trailing whitespace from val. */
		while (isspace(*val) && *val != '\0')
			val++;
		if (*val == '\0')
			continue;
		c = &val[strlen(val) - 1];
		while (isspace(*c) && c >= val) {
			*c = '\0';
			c--;
		}
//		printf("key: \"%s\" val: \"%s\"\n", key, val);

		if (check_vendor && !strcmp(key, VENDOR_KEY)) {
			/* No intel == no ht */
			if (strcmp(val, VENDOR_VAL))
				goto out_close;
			check_vendor = 0;
		} else if (!strcmp(key, FLAGS_KEY)) {
			for (flag = val; flag && *flag; flag = c) {
				c = strchr(flag, FLAGS_DELIM);
				if (c) {
					*c = '\0';
					if (c < &line[LINE_MAX])
						c++;
					else
						c = NULL;
				}
//				printf("\"flag: %s\"\n", flag);
				if (!strcmp(flag, HT_FLAG))
					return 1;
			}
			/* No 'ht' in flags? We're done. */
			goto out_close;
		}
	}
	if (ferror(fp))
		err = errno;

out_close:
	fclose(fp);
out:
	if (err)
		fprintf(stderr,
			"Error %d (\"%s\") while checking /proc/cpuinfo for "
			"hyperthreading -- will assume ht is off.\n", err,
			strerror(err));
	return ret;
}

void get_num_cpus(unsigned int *nr_phys, unsigned int *nr_log)
{
	int ht;

	*nr_phys = *nr_log = sysconf(_SC_NPROCESSORS_ONLN);
	ht = detect_ht();
	if (ht && *nr_phys >= 2)
		*nr_phys /= 2;

	dprintf("Detected %u logical and %u physical cpus (ht is %s).\n",
		*nr_log, *nr_phys, ht ? "on" : "off");
}
