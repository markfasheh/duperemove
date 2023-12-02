PENDING
---

**Notable changes**:
 * Files are no longer invalidated when renamed.

Version 0.14
---

**Notable changes**:
 * Batching has been reimplemented on top of the dedupe\_seq.
 * The "scan" phase has been reimplemented (see 8264336ea2a3b78e3bdce162fc389d02338af326 for details).
 * Filesystem locking has been implemented. See f3947e9606f103417537974bc3dda4f6254c4503 for details.

Version 0.13
---

**Notable changes**:
 * Add a new dedupe option: `[no]rescan_files`. It will increase performance in some use cases.
 * New behaviors from v0.12 has been consolidated. Extent-based lookup is always enabled, as is fiemap. The v2 hashfile is no longer supported.
 * Hashfile are now updated after deduplication, to reflect the new physical offsets. This avoid (re)deduplicating extents in some cases.
 * Partial mode has been enhanced to support batching. The overall performance of this mode (which was previously known as "block-based mode") has been improved.
 * All files are now open in readonly mode.
 * Hashfile version has been increased to reflect the new database behaviors. Previous hashfiles are not compatible.
 * Always compute a hash for the entire file. This let us deduplicate same files easily, regardless of their extents mappings.
 * Deduplicating only parts of a file can be disabled using the `[no]only_whole_files` dedupe option.
 * Hashfiles with unsupported features or hash algorithm are now recreated transparently. Migration of the old content is not implemented.
 * Relative exclude patterns are no longer silently ingested. Such patterns are now rebuilt on top of the current working directory.
 * Batching is now set to 1024 by default.

Version 0.12
---

**Notable changes**:
 * Duplication lookup is now based on extents. This leads to a massive increase of the performances. Block-based lookup is still possible via `--dedupe-options=partial`.
 * Following that change, a new hashfile format has been introduced. Previous hashfile format is still supported when extents lookup are disabled, this is not recommended.
 * Batching has been implemented. When enabled with the `-B <batchsize>` option, `duperemove` will run the deduplication phase every `<batchsize>` scanned files. This is meant to help running `duperemove` on large dataset, with small blocksize, or on memory-constrained systems.
 * All hash algorithms has been removed and replaced by xxh128. This variant is as robust as murmur3 while being faster. Choosing a hash function via the `--hash` option has been removed. Hashfiles built with other algorithm must be removed.
