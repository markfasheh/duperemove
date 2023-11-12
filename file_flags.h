#ifndef __FILE_FLAGS_H__
#define __FILE_FLAGS_H__

/* Fiemap flags that would cause us to mark the extent as undeduplicable */
#define FIEMAP_SKIP_FLAGS	(FIEMAP_EXTENT_DATA_INLINE|FIEMAP_EXTENT_UNWRITTEN)

/*
 * The following flags may be used in the hashfile.
 * Do not change the values recklessly.
 */
/* File is inlined. We store no extents nor hashes for it.
 * We should not try to deduplicate this file, won't work anyway.
 */
#define FILE_INLINED		0x0001

#endif
