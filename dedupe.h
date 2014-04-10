#ifndef	__DEDUPE_H__
#define	__DEDUPE_H__

#include "list.h"
#include "btrfs-ioctl.h"

struct dedupe_ctxt {

	/*
	 * Starting len/file off saved for the callers convenience -
	 * the ones below can change during dedupe operations.
	 */
	uint64_t	orig_len;
	uint64_t	orig_file_off;

	uint64_t	len;
	struct filerec	*ioctl_file;
	uint64_t	ioctl_file_off;

	/* Next two are used for sanity checking */
	unsigned int		max_queable;
	unsigned int		num_queued;

	unsigned int		same_size;
	/*
	 * filerecs that are being used to dedupe against the ioctl file.
	 *	queued: filerec is awaiting dedupe
	 *	in_progress: currently undergoing dedupe operations
	 *	completed: results of dedupe for this file are available
	 */
	struct list_head	queued;
	struct list_head	in_progress;
	struct list_head	completed;

	struct btrfs_ioctl_same_args	*same;
};

struct dedupe_ctxt *new_dedupe_ctxt(unsigned int max_extents, uint64_t loff,
				    uint64_t elen, struct filerec *ioctl_file);
void free_dedupe_ctxt(struct dedupe_ctxt *ctxt);
void add_extent_to_dedupe(struct dedupe_ctxt *ctxt, uint64_t loff, uint64_t len,
			  struct filerec *file);
int dedupe_extents(struct dedupe_ctxt *ctxt);
void get_dedupe_result(struct dedupe_ctxt *ctxt, int idx, int *status,
		       uint64_t *off, uint64_t *bytes_deduped,
		       struct filerec **file);

int pop_one_dedupe_result(struct dedupe_ctxt *ctxt, int *status,
			  uint64_t *off, uint64_t *bytes_deduped,
			  struct filerec **file);
void get_target_dedupe_info(struct dedupe_ctxt *ctxt, uint64_t *orig_loff,
			    uint64_t *orig_len, struct filerec **file);

#endif	/* __BTRFS_IOCTL_H__ */
