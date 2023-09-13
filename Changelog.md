PENDING
---

**Notable changes**:
 * Add a new dedupe option: `[no]rescan\_files`. It will increase performance in some use cases.
 * New behaviors from v0.12 has been consolidated. Extent-based lookup is always enabled, as is fiemap. The v2 hashfile is no longer supported.
 * Hashfile are now updated after deduplication, to reflect the new physical offsets. This avoid (re)deduplicating extents in some cases.
 * Partial mode has been enhanced to support batching. The overall performance of this mode (which was previously known as "block-based mode") has been improved.
 * All files are now open in readonly mode.

Version 0.12
---

**Notable changes**:
 * Duplication lookup is now based on extents. This leads to a massive increase of the performances. Block-based lookup is still possible via `--dedupe-options=partial`.
 * Following that change, a new hashfile format has been introduced. Previous hashfile format is still supported when extents lookup are disabled, this is not recommended.
 * Batching has been implemented. When enabled with the `-B <batchsize>` option, `duperemove` will run the deduplication phase every `<batchsize>` scanned files. This is meant to help running `duperemove` on large dataset, with small blocksize, or on memory-constrained systems.
 * All hash algorithm has been removed and replaced by xxh128. This variant is as robust as murmur3 while being faster. Choosing a hash function via the `--hash` option has been removed. Hashfiles built with other algorithm must be removed.
