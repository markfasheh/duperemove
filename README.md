This README is for the development branch of duperemove. If you're looking
for a stable version which is continually updated with fixes, please see
[v0.09 branch](https://github.com/markfasheh/duperemove/tree/v0.09-branch).

# Duperemove

Duperemove is a simple tool for finding duplicated extents and
submitting them for deduplication. When given a list of files it will
hash their contents on a block by block basis and compare those hashes
to each other, finding and categorizing extents that match each
other. When given the -d option, duperemove will submit those
extents for deduplication using the btrfs-extent-same ioctl.

Duperemove has two major modes of operation one of which is a subset
of the other.


## Readonly / Non-deduplicating Mode

When run without -d (the default) duperemove will print out one or
more tables of matching extents it has determined would be ideal
candidates for deduplication. As a result, readonly mode is useful for
seeing what duperemove might do when run with '-d'. The output could
also be used by some other software to submit the extents for
deduplication at a later time.

It is important to note that this mode will not print out *all*
instances of matching extents, just those it would consider for
deduplication.

Generally, duperemove does not concern itself with the underlying
representation of the extents it processes. Some of them could be
compressed, undergoing I/O, or even have already been deduplicated. In
dedupe mode, the kernel handles those details and therefore we try not
to replicate that work.


## Deduping Mode

This functions similarly to readonly mode with the exception that the
duplicated extents found in our "read, hash, and compare" step will
actually be submitted for deduplication. An estimate of the total data
deduplicated will be printed after the operation is complete. This
estimate is calculated by comparing the total amount of shared bytes
in each file before and after the dedupe.


See the duperemove man page for further details about running duperemove.


# Requirements

The latest stable code can be found in [v0.09-branch](https://github.com/markfasheh/duperemove/tree/v0.09-branch).

Kernel: Duperemove needs a kernel version equal to or greater than 3.13

Libraries: Duperemove uses glib2 and sqlite3.


# FAQ

Please see the FAQ file [provided in the duperemove
source](https://github.com/markfasheh/duperemove/blob/master/FAQ.md)

# Usage Examples

Duperemove takes a list of files and directories to scan for
dedupe. If a directory is specified, all regular files within it will
be scanned. Duperemove can also be told to recursively scan
directories with the '-r' switch. If '-h' is provided, duperemove will
print numbers in powers of 1024 (e.g., "128K").

Assume this abitrary layout for the following examples.

    .
    ├── dir1
    │   ├── file3
    │   ├── file4
    │   └── subdir1
    │       └── file5
    ├── file1
    └── file2

This will dedupe files 'file1' and 'file2':

    duperemove -dh file1 file2

This does the same but adds any files in dir1 (file3 and file4):

    duperemove -dh file1 file2 dir1

This will dedupe exactly the same as above but will recursively walk
dir1, thus adding file5.

    duperemove -dhr file1 file2 dir1/


An actual run, output will differ according to duperemove version.

    duperemove -dhr file1 file2 dir1
    Using 128K blocks
    Using hash: SHA256
    Using 2 threads for file hashing phase
    csum: file1     [1/5]
    csum: file2     [2/5]
    csum: dir1/file3       [3/5]
    csum: dir1/subdir1/file5       [4/5]
    csum: dir1/file4       [5/5]
    Hashed 80 blocks, resulting in 17 unique hashes. Calculating duplicate
    extents - this may take some time.
    [########################################]
    Search completed with no errors.
    Simple read and compare of file data found 2 instances of extents that might
    benefit from deduplication.
    Start           Length          Filename (2 extents)
    0.0     2.0M    "file2"
    0.0     2.0M    "dir1//file4"
    Start           Length          Filename (3 extents)
    0.0     2.0M    "file1"
    0.0     2.0M    "dir1//file3"
    0.0     2.0M    "dir1//subdir1/file5"
    Dedupe 1 extents with target: (0.0, 2.0M), "file2"
    Dedupe 2 extents with target: (0.0, 2.0M), "file1"
    Kernel processed data (excludes target files): 6.0M
    Comparison of extent info shows a net change in shared extents of: 10.0M
