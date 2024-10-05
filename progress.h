#ifndef	__PROGRESS_H__
#define	__PROGRESS_H__

#include <stdint.h>

#include "glib.h"

enum pscan_thread_status {
	thread_idle,
	thread_scanning,
	thread_waiting_lock,
	thread_committing,
};

struct pscan_thread {
	/* Thread id owning this struct */
	pid_t				tid;

	/* Tracks data for the entire thread lifetime */
	uint64_t			total_scanned_files;
	uint64_t			total_scanned_bytes;

	/* Tracks data for the file currently being processed */
	uint64_t			file_scanned_bytes;
	uint64_t			file_total_bytes;
	char				file_path[PATH_MAX + 1];

	enum pscan_thread_status	status;
};

struct pscan_global {
	uint64_t		total_files_count;
	uint64_t		total_bytes_count;
	bool			listing_completed;

	/* Each thread tracks its own progress separately */
	GMutex			mutex;
	unsigned int		thread_count;
	struct pscan_thread	**threads;
};

void pscan_finish_listing();

/* Used to increment the global todo list */
void pscan_set_progress(uint64_t added_files, uint64_t added_bytes);

/* Used by each scan threads to grab its own struct pscan_thread */
struct pscan_thread *pscan_register_thread(pid_t tid);

/*
 * Setup the pty and start the progress thread
 * The thread will run until the scan is done, that is:
 * - the listing is completed - pscan_finish_listing() has been called
 * - the sum of all threads progresses equals to the global totals
 */
void pscan_run();

/*
 * Wait for the progress thread to finish
 * Also cleanup per-thread progresses and print the global totals
 */
void pscan_join();

/*
 * Reset file tracking data
 * This is used by the csum_whole_file(): regardless of its outcome,
 * the thread is set as idle, total_scanned_files is incremented and
 * total_scanned_bytes is fed up to the file size (in case it shrank)
 */
void pscan_reset_thread(struct pscan_thread **progress);

bool is_progress_printer_running();

/*
 * The progress thread overwrites its area.
 * This function is used to write something before that area
 */
void pscan_printf(char *fmt, ...);

/*
 * Start the "extent search" progress thread
 * The thread will run until the search is done, that is when we
 * processed all filerecs
 */
void psearch_run(uint64_t num_filerecs);

/*
 * Wait for the progress thread to finish
 */
void psearch_join();

/*
 * extent search: update the number of processed filerecs
 */
void psearch_update_processed_count(unsigned int processed);

#endif	/* __PROGRESS_H__ */
