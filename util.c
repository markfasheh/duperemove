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
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <regex.h>
#include <dirent.h>
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
		eprintf("ERROR: size value is empty\n");
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
			eprintf("ERROR: Unknown size descriptor "
				"'%c'\n", c);
			exit(1);
		}
	}
	if (s[i] && s[i+1]) {
		eprintf("ERROR: Illegal suffix contains "
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
	return snprintf(str, str_bytes, "%.1f%sB", fraction,
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

static int get_core_count_fallback(unsigned int *nr_phys, unsigned int *nr_log)
{
	char path[PATH_MAX];
	int ret = 0;
	DIR *dirp;
	regex_t regex;
	regmatch_t pmatch[1];
	size_t nmatch = 1;
	struct dirent *entry;
	int physical = 0 , logical = 0;

	ret = snprintf(path, PATH_MAX, "/sys/devices/system/cpu/");
	if (ret < 0)
		return ret;

	dirp = opendir(path);
	if (dirp == NULL)
		return errno;

	ret = regcomp(&regex, "cpu[[:digit:]]+", REG_EXTENDED);
	if (ret < 0)
		goto out_freedir;

	do {
		entry = readdir(dirp);
		if (entry) {
			FILE *filp;
			int sibling1, sibling2;
			if (regexec(&regex, entry->d_name, nmatch, pmatch,
				    0) != 0)
				continue;
#define FMT_STRING  "/sys/devices/system/cpu/%s/topology/thread_siblings_list"
			ret = snprintf(path, PATH_MAX, FMT_STRING,
				       entry->d_name);
			if (ret < 0)
				goto out;

			// When HT is turned off hyperthreads won't have
			// topology/ subdirectory
			filp = fopen(path, "r");
			if (filp == NULL)
				continue;

			physical++;
			ret = fscanf(filp, "%d,%d", &sibling1, &sibling2);
			logical += ret;
			fclose(filp);

		}
	} while (entry != NULL);

	// If HT is on logical/physical would have been counted twice due
	// to the way /sys/devices/system/cpu/ is populated, in this case
	// adjust counts.
	if (logical > physical) {
		logical /= 2;
		physical /= 2;
	}

	*nr_log = logical;
	*nr_phys = physical;

out:
	regfree(&regex);
out_freedir:
	closedir(dirp);

	return ret;
}

int get_core_count(unsigned int *nr_phys, unsigned int *nr_log)
{
	char *line = NULL;
	size_t n = 0;;
	int ret;
	unsigned int logical = 0;
	unsigned int physical = 0;
	uint64_t sockets[64] = {0,}; /* supports up to 64 sockets with
					64 cores per socket */

	FILE *fp = popen("lscpu -p", "r");
	if (fp == NULL) {
		eprintf("ERROR: Can't start lscpu\n");
		return -EINVAL;
	}

	while ((ret = getline(&line, &n, fp) > 0)) {
		unsigned int core, socket, unused;
		/* Skip comment lines */
		if (line[0] == '#')
			continue;
		logical++;

		/* We only care about the core/socket id */
		ret = sscanf(line, "%u,%u,%u", &unused, &core, &socket);
		if (ret != 3) {
			dprintf("Can't parse lscpu line: %s\n", line);
			continue;
		}

		if (!(sockets[socket] & (1<<core))) {
			physical++;
			sockets[socket] |= (1<<core);
		}
	}

	if (logical == 0  || physical  == 0)
		ret = -EINVAL;
	else {
		*nr_phys = physical;
		*nr_log = logical;
	}

	free(line);
	pclose(fp);

	return ret;
}

void get_num_cpus(unsigned int *nr_phys, unsigned int *nr_log)
{
	int ht = 0;
	int ret = get_core_count(nr_phys, nr_log);

	if (ret < 0) {
		ret = get_core_count_fallback(nr_phys, nr_log);
		if (ret < 0)
			*nr_phys = *nr_log = sysconf(_SC_NPROCESSORS_ONLN);
	} else
		ht = *nr_log > *nr_phys;

	dprintf("Detected %u logical and %u physical cpus (ht %s).\n",
		*nr_log, *nr_phys, ht ? "is on" :
		ret < 0 ? "detection broken" : "is off");
}

int increase_limits(void) {
	struct rlimit cur_r;
	struct rlimit new_r;
	int ret;

	ret = getrlimit(RLIMIT_NOFILE, &cur_r);
	if (ret < 0)
		return -errno;

	new_r.rlim_cur = cur_r.rlim_max;
	new_r.rlim_max = cur_r.rlim_max;
	ret = setrlimit(RLIMIT_NOFILE, &new_r);

	if (ret < 0)
		return -errno;

	vprintf("Increased open file limit from %llu to %llu.\n",
		(unsigned long long)cur_r.rlim_cur,
		(unsigned long long)new_r.rlim_cur);
	return 0;
}

void debug_print_uuid(uuid_t uuid)
{
	char buf[37];
	uuid_unparse(uuid, buf);
	eprintf("%s", buf);
}
