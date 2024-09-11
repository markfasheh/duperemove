/*
 * progress.c
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
#include <sys/ioctl.h>

#include "debug.h"
#include "opt.h"
#include "util.h"
#include "progress.h"

/*
 * This implements a multi progressbar
 * To do this, it reserves n + 3 lines from the bottom
 * of the screen and save the position
 * Those lines will be used in the following way:
 * one line per thread (up to n lines), and then 3 lines for the
 * totals:
 * ### thread 1 progress
 * ### thread 2 progress
 * ###
 * ### thread n progress
 * ### 	Total bytes
 * ### 	Total files
 * ### 	Listing status
 *
 * n is derived from the maximum number of threads, not from the actual
 * number of thread. In such cases, empty lines will follow the "totals"
 * block.
 *
 * Every time the progress thread tries to print the progress, it:
 * - jump back to the saved position
 * - print one line for each running thread, cleaning the existing line
 * - print the totals (again, cleaning the existing line)
 *
 * A function pscan_printf() is provided to print data while the progress
 * thread is running
 * It will grab the lock and print the data before the "progress" area:
 * - jump back to the saved position
 * - print the data
 * - reserves n + 3 lines
 * - save the new position so that the data is not overwritten
 *
 * If stdout is not a tty, no asci code are printed, so this acts as
 * an append-only progressbar.
 */

struct pscan_global pscan = {};
static GThread *printer = NULL;
bool tty;
unsigned int w_col;

/* Sums of the per-thread stats */
static uint64_t files_scanned, bytes_scanned;

#define s_save_pos() if (tty) printf("\33[s");
#define s_restore_pos() if (tty) printf("\33[u");
#define s_clear() if (tty) printf("\33[J");
#define s_printf(args...) do { if (tty) printf("\33[K"); printf(args); } while (0)

#define percent(val1, val2) ((double) val1 / (double) val2 * 100)

void pscan_finish_listing(void)
{
	pscan.listing_completed = true;
}

void pscan_set_progress(uint64_t added_files, uint64_t added_bytes)
{
	pscan.total_files_count += added_files;
	pscan.total_bytes_count += added_bytes;
}

#define BUF_LEN 10*1024
static void print_thread_progress(struct pscan_thread *tprogress)
{
	char buf[BUF_LEN];

	switch (tprogress->status) {
	case thread_idle:
		snprintf(buf, BUF_LEN, "[%u] idle", tprogress->tid);
		break;
	case thread_scanning:
		snprintf(buf, BUF_LEN, "[%u] %-20s%s: %s/%s (%05.2f%%)",
			tprogress->tid,
			"checksumming:",
			tprogress->file_path,
			pretty_size(tprogress->file_scanned_bytes),
			pretty_size(tprogress->file_total_bytes),
			percent(tprogress->file_scanned_bytes, tprogress->file_total_bytes));
		break;
	case thread_waiting_lock:
		snprintf(buf, BUF_LEN, "[%u] %-20s%s (size: %s)",
			tprogress->tid,
			"waiting for lock:",
			tprogress->file_path,
			pretty_size(tprogress->file_total_bytes));
		break;
	case thread_committing:
		snprintf(buf, BUF_LEN, "[%u] %-20s%s (size: %s)",
			tprogress->tid,
			"committing:",
			tprogress->file_path,
			pretty_size(tprogress->file_total_bytes));
		break;
	}

	/* Truncate the output to keep at most one line per thread */
	s_printf("%.*s\n", w_col, buf);
}

static void print_total_progress(void)
{
	s_printf("\tFiles scanned: %lu/%lu (%05.2f%%)\n",
	      files_scanned, pscan.total_files_count,
	      (double)files_scanned / (double)pscan.total_files_count * 100);
	s_printf("\tBytes scanned: %s/%s (%05.2f%%)\n",
	      pretty_size(bytes_scanned),
	      pretty_size(pscan.total_bytes_count),
	      (double)bytes_scanned / (double)pscan.total_bytes_count * 100);
	s_printf("\tFile listing: %s\n",
		pscan.listing_completed ? "completed" : "in progress");
}

static void prepare_screen_area(void)
{
	/*
	 * Prepare one empty line for each scan threads
	 * plus one line for the total.
	 * This is required to bypass the scrolling and let us
	 * save/restore the cursor position.
	 */
	for (unsigned int i = 0; i < options.io_threads + 3; i++)
		s_printf("\n");

	/* Go back to the first line */
	printf("\33[%iA", options.io_threads + 3);

	/*
	 * Save the cursor position.
	 * We will restore it every time we print progress.
	 */
	s_save_pos()
}

static void *print_progress(void)
{
	files_scanned = 0;
	bytes_scanned = 0;

	s_restore_pos();

	for (unsigned int i = 0; i < pscan.thread_count; i++) {
		print_thread_progress(pscan.threads[i]);
		files_scanned += pscan.threads[i]->total_scanned_files;
		bytes_scanned += pscan.threads[i]->total_scanned_bytes;
	}

	print_total_progress();

	return NULL;
}

static void *progress_thread(void *)
{
	struct winsize w;
	do {
		/* Refresh the tty properties */
		if (tty) {
			ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
			w_col = w.ws_col;
		} else {
			w_col = UINT_MAX;
		}

		g_mutex_lock(&pscan.mutex);
		print_progress();
		g_mutex_unlock(&pscan.mutex);

		/* Do not waste too much cpu */
		usleep(1000 * (tty ? 100 : 1000));
	} while (!pscan.listing_completed
		|| files_scanned != pscan.total_files_count
		|| bytes_scanned != pscan.total_bytes_count);

	return NULL;
}

struct pscan_thread *pscan_register_thread(pid_t tid)
{
	struct pscan_thread *tprogress = calloc(1, sizeof(struct pscan_thread));
	tprogress->tid = tid;

	g_mutex_lock(&pscan.mutex);
	pscan.threads = realloc(pscan.threads, (pscan.thread_count + 1) *
						sizeof(struct pscan_thread *));
	pscan.threads[pscan.thread_count] = tprogress;
	pscan.thread_count++;
	g_mutex_unlock(&pscan.mutex);
	return tprogress;
}

void pscan_run()
{
	tty = isatty(STDOUT_FILENO);

	if (tty) {
		/* hide the cursor */
		printf("\33[?25l");

		prepare_screen_area();
	}

	/* Will abort on failure */
	printer = g_thread_new("progress_printer", progress_thread, NULL);
}

void pscan_join()
{
	g_thread_join(printer);

	/* Show the cursor again */
	printf("\33[?25h");

	/* Clear the screen from all thread-progress */
	s_restore_pos();
	s_clear();
	s_restore_pos();

	print_total_progress();

	for (unsigned int i = 0; i < pscan.thread_count; i++)
		free(pscan.threads[i]);

	printer = NULL;
}

void pscan_reset_thread(struct pscan_thread **progress)
{
	if (!progress || !*progress)
		return;
	uint64_t scanned = (*progress)->file_scanned_bytes;
	uint64_t total = (*progress)->file_total_bytes;

	(*progress)->status = thread_idle;
	/*
	 * The file may have shrinked between the statx and
	 * the end of the scan.
	 * Does not matter much, we fake-fill the missing bytes
	 * so the global progress don't diverge much
	 */
	if (scanned < total)
		(*progress)->total_scanned_bytes += total - scanned;

	/*
	 * Also, the file may have grow.
	 */
	if (scanned > total)
		(*progress)->total_scanned_bytes -= scanned - total;

	(*progress)->total_scanned_files++;
	(*progress)->file_path[0] = '\0';
}

bool is_pscan_running()
{
	return printer ? true : false;
}

void pscan_printf(char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	g_mutex_lock(&pscan.mutex);
	if (tty) {
		s_restore_pos();
		s_clear();
		s_restore_pos();
	}

	vfprintf(stdout, fmt, args);

	if (tty) {
		s_save_pos();
		prepare_screen_area();
	}
	va_end(args);

	/*
	 * We reprint the progress immediately to reduce
	 * the time during which the screen is left empty:
	 * between the prepare_screen_area() and the progress_thread()'s
	 * next iteration.
	 */
	print_progress();
	g_mutex_unlock(&pscan.mutex);
}
