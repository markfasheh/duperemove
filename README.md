This README is for duperemove v0.11.

# Duperemove

Duperemove is a simple tool for finding duplicated extents and
submitting them for deduplication. When given a list of files it will
hash their contents on a extent by extent basis and compare those hashes
to each other, finding and categorizing extents that match each
other. Optionally, a per-block hash can be applied for further duplication lookup.
When given the -d option, duperemove will submit those
extents for deduplication using the Linux kernel extent-same ioctl.

Duperemove can store the hashes it computes in a 'hashfile'. If
given an existing hashfile, duperemove will only compute hashes
for those files which have changed since the last run.  Thus you can run
duperemove repeatedly on your data as it changes, without having to
re-checksum unchanged data.

Duperemove can also take input from the [fdupes](https://github.com/adrianlopezroche/fdupes) program.

See [the duperemove man page](http://markfasheh.github.io/duperemove/duperemove.html) for further details about running duperemove.


# Requirements

The latest stable code can be found in [the release page](https://github.com/markfasheh/duperemove/releases)

Kernel: Duperemove needs a kernel version equal to or greater than 3.13

Libraries: Duperemove uses glib2 and sqlite3.


# FAQ

Please see the FAQ section in [the duperemove man page](http://markfasheh.github.io/duperemove/duperemove.html#10)

For bug reports and feature requests please use [the github issue tracker](https://github.com/markfasheh/duperemove/issues)


# Examples

Please see the examples section of [the duperemove man
page](http://markfasheh.github.io/duperemove/duperemove.html#7)
for a complete set of usage examples, including hashfile usage.

## A simple example, with program output

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

    Using 128K blocks
    Using hash: murmur3
    Using 4 threads for file hashing phase
    csum: /btrfs/file1 	[1/5] (20.00%)
    csum: /btrfs/file2 	[2/5] (40.00%)
    csum: /btrfs/dir1/subdir1/file5 	[3/5] (60.00%)
    csum: /btrfs/dir1/file3 	[4/5] (80.00%)
    csum: /btrfs/dir1/file4 	[5/5] (100.00%)
    Total files:  5
    Total hashes: 80
    Loading only duplicated hashes from hashfile.
    Hashing completed. Calculating duplicate extents - this may take some time.
    Simple read and compare of file data found 3 instances of extents that might benefit from deduplication.
    Showing 2 identical extents of length 512.0K with id 0971ffa6
    Start		Filename
    512.0K	"/btrfs/file1"
    1.5M	"/btrfs/dir1/file4"
    Showing 2 identical extents of length 1.0M with id b34ffe8f
    Start		Filename
    0.0	"/btrfs/dir1/file4"
    0.0	"/btrfs/dir1/file3"
    Showing 3 identical extents of length 1.5M with id f913dceb
    Start		Filename
    0.0	"/btrfs/file2"
    0.0	"/btrfs/dir1/file3"
    0.0	"/btrfs/dir1/subdir1/file5"
    Using 4 threads for dedupe phase
    [0x147f4a0] Try to dedupe extents with id 0971ffa6
    [0x147f770] Try to dedupe extents with id b34ffe8f
    [0x147f680] Try to dedupe extents with id f913dceb
    [0x147f4a0] Dedupe 1 extents (id: 0971ffa6) with target: (512.0K, 512.0K), "/btrfs/file1"
    [0x147f770] Dedupe 1 extents (id: b34ffe8f) with target: (0.0, 1.0M), "/btrfs/dir1/file4"
    [0x147f680] Dedupe 2 extents (id: f913dceb) with target: (0.0, 1.5M), "/btrfs/file2"
    Kernel processed data (excludes target files): 4.5M
    Comparison of extent info shows a net change in shared extents of: 5.5M


# Links of interest

[The duperemove wiki](https://github.com/markfasheh/duperemove/wiki)
has both design and performance documentation.

[duperemove-tests](https://github.com/markfasheh/duperemove-tests) has
a growing assortment of regression tests.

[Duperemove web page](http://markfasheh.github.io/duperemove/)
