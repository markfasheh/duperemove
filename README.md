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

Kernel: Duperemove needs a kernel version equal to or greater than 3.13

Libraries: Duperemove uses glib2 and optionally libgcrypt for hashing.


# Frequently Asked Questions

### Is there an upper limit to the amount of data duperemove can process?

v0.08 of duperemove has been tested on small numbers of VMS or iso
files (5-10) it can probably scale up to 50 or so.

v0.09 is much faster at hashing and cataloging extents and therefore
can handle a larger data set. My own testing is typically with a
filesystem of about 750 gigabytes and millions of files.


### Why does it not print out all duplicate extents?

Internally duperemove is classifying extents based on various criteria
like length, number of identical extents, etc. The printout we give is
based on the results of that classification.


### How can I find out my space savings after a dedupe?

Duperemove will print out an estimate of the saved space after a
dedupe operation for you. You can also do a df before the dedupe
operation, then a df about 60 seconds after the operation. It is
common for btrfs space reporting to be 'behind' while delayed updates
get processed, so an immediate df after deduping might not show any
savings.


### Why is the total deduped data report an estimate?

At the moment duperemove can detect that some underlying extents are
shared with other files, but it can not resolve which files those
extents are shared with.

Imagine duperemove is examing a series of files and it notes a shared
data region in one of them. That data could be shared with a file
outside of the series. Since duperemove can't resolve that information
it will account the shared data against our dedupe operation while in
reality, the kernel might deduplicate it further for us.


### Why are my files showing dedupe but my disk space is not shrinking?

This is a little complicated, but it comes down to a feature in Btrfs
called _bookending_. The Btrfs wiki explains this in [detail]
(http://en.wikipedia.org/wiki/Btrfs#Extents).

Essentially though, the underlying representation of an extent in
Btrfs can not be split (with small exception). So sometimes we can end
up in a situation where a file extent gets partially deduped (and the extents marked as shared) but the
underlying extent item is not freed or truncated.


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
