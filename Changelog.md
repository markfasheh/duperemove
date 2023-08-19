PENDING
---

**Notable changes**:
 * Add a new dedupe option: `[no]rescan\_files`. It will increase performance in some use cases.

Version 0.12
---

**Notable changes**:
 * Duplication lookup is now based on extents. This leads to a massive increase of the performances. Block-based lookup is still possible via `--dedupe-options=partial`.
 * Following that change, a new hashfile format has been introduced. Previous hashfile format is still supported when extents lookup are disabled, this is not recommended.
 * Batching has been implemented. When enabled with the `-B <batchsize>` option, `duperemove` will run the deduplication phase every `<batchsize>` scanned files. This is meant to help running `duperemove` on large dataset, with small blocksize, or on memory-constrained systems.
 * All hash algorithm has been removed and replaced by xxh128. This variant is as robust as murmur3 while being faster. Choosing a hash function via the `--hash` option has been removed. Hashfiles built with other algorithm must be removed.
