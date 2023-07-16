#ifndef __FILE_FLAGS_H__
#define __FILE_FLAGS_H__

/* Fiemap flags that would cause us to skip comparison of the block */
#define FIEMAP_SKIP_FLAGS	(FIEMAP_EXTENT_DATA_INLINE|FIEMAP_EXTENT_UNWRITTEN)

#define FILE_BLOCK_SKIP_COMPARE	0x0001
#define FILE_BLOCK_DEDUPED	0x0002
#define FILE_BLOCK_HOLE		0x0004
#define FILE_BLOCK_PARTIAL	0x0008

#endif
