#ifndef	__FIEMAP_H__
#define	__FIEMAP_H__

#include <linux/fiemap.h>
#include <sys/types.h>

/*
 * Given a filled fiemap structure, extract the struct fiemap_extent
 * which covers the loff offset.
 * If index is not NULL, then it will be filled with the extent's index.
 * If no extent is found, returns NULL and index is garbage.
 * The returned value must not be used after fiemap is freed, and must not
 * be freed directly either.
 */
struct fiemap_extent *get_extent(struct fiemap *fiemap, size_t loff,
				 unsigned int *index);

/*
 * Extract the extents mapping of a file.
 */
struct fiemap *do_fiemap(int fd);
#endif	/* __FIEMAP_H__ */
