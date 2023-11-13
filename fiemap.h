#ifndef	__FIEMAP_H__
#define	__FIEMAP_H__

#include <linux/fiemap.h>
#include <sys/types.h>
#include <stdint.h>

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
 * May not return all extents if the file changed while this function is
 * running.
 */
struct fiemap *do_fiemap(int fd);

/*
 * Count how much of the area between start_off and end_off is shared.
 */
int fiemap_count_shared(int fd, size_t start_off, size_t end_off, size_t *shared);
#endif	/* __FIEMAP_H__ */
