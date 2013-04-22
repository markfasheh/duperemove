#ifndef	__DEDUPE_H__
#define	__DEDUPE_H__

#include "btrfs-ioctl.h"

struct dedupe_ctxt {
	unsigned int	max_extents;	/* used for sanity checking */

	uint64_t	len;
	int		ioctl_fd;
	unsigned int	ioctl_fd_index;
	uint64_t	ioctl_fd_off;

	unsigned int	*filerec_index;

	struct btrfs_ioctl_same_args	*same;
};

struct dedupe_ctxt *new_dedupe_ctxt(unsigned int num_extents, uint64_t loff,
				    uint64_t elen,  int fd,
				    unsigned int filerec_index);
void free_dedupe_ctxt(struct dedupe_ctxt *ctxt);
void add_extent_to_dedupe(struct dedupe_ctxt *ctxt, uint64_t loff, uint64_t len,
			  int fd, unsigned int filerec_index);
int dedupe_extents(struct dedupe_ctxt *ctxt);
void get_dedupe_result(struct dedupe_ctxt *ctxt, int idx, int *status,
		       uint64_t *off, uint64_t *bytes_deduped,
		       unsigned int *filerec_index);

static inline int num_dedupe_requests(struct dedupe_ctxt *ctxt)
{
	return ctxt->same->dest_count;
}
#endif	/* __BTRFS_IOCTL_H__ */
