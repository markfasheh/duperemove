#ifndef	__DEDUPE_H__
#define	__DEDUPE_H__

#include "btrfs-ioctl.h"

struct dedupe_ctxt {
	unsigned int	max_extents;	/* used for sanity checking */

	uint64_t	len;
	struct filerec	*ioctl_file;
	uint64_t	ioctl_file_off;

	struct filerec	**filerec_array;

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

static inline int num_dedupe_requests(struct dedupe_ctxt *ctxt)
{
	return ctxt->same->dest_count;
}
#endif	/* __BTRFS_IOCTL_H__ */
