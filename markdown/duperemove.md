---
title: Duperemove
section: 8
header: System Manager’s Manual
footer: duperemove 0.12
date: 07 Aug 2023
---
# NAME
`duperemove` - Find duplicate extents and submit them for deduplication

# SYNOPSIS
**duperemove** *[options]* *files...*

# DESCRIPTION
`duperemove` is a simple tool for finding duplicated extents and
submitting them for deduplication. When given a list of files it will
hash the contents of their extents and compare those hashes to each
other, finding and categorizing extents that match each other. When
given the `-d` option, `duperemove` will submit those extents
for deduplication using the Linux kernel FIDEDUPERANGE ioctl.

`duperemove` can store the hashes it computes in a `hashfile`. If
given an existing hashfile, `duperemove` will only compute hashes
for those files which have changed since the last run. Thus you can run
`duperemove` repeatedly on your data as it changes, without having to
re-checksum unchanged data. For more on hashfiles see the
`--hashfile` option below as well as the `Examples` section.

`duperemove` can also take input from the `fdupes` program, see the
`--fdupes` option below.

# GENERAL
Duperemove has two major modes of operation, one of which is a subset
of the other.

## Readonly / Non-deduplicating Mode

When run without `-d` (the default) duperemove will print out one or
more tables of matching extents it has determined would be ideal
candidates for deduplication. As a result, readonly mode is useful for
seeing what duperemove might do when run with `-d`.

Generally, duperemove does not concern itself with the underlying
representation of the extents it processes. Some of them could be
compressed, undergoing I/O, or even have already been deduplicated. In
dedupe mode, the kernel handles those details and therefore we try not
to replicate that work.

## Deduping Mode

This functions similarly to readonly mode with the exception that the
duplicated extents found in our "read, hash, and compare" step will
actually be submitted for deduplication. Extents that have already
been deduped will be skipped. An estimate of the total data
deduplicated will be printed after the operation is complete. This
estimate is calculated by comparing the total amount of shared bytes
in each file before and after the dedupe.

# OPTIONS

## Common options

`files` can refer to a list of regular files and directories or be
a hyphen (-) to read them from standard input.
If a directory is specified, all regular files within it will also be
scanned. Duperemove can also be told to recursively scan directories with
the `-r` switch.

**-r**
  ~ Enable recursive dir traversal.

**-d**
  ~ De-dupe the results - only works on `btrfs` and `xfs`. Use this option
twice to disable the check and try to run the ioctl anyway.

**\--hashfile**=`hashfile`
  ~ Use a file for storage of hashes instead of memory. This option drastically
reduces the memory footprint of duperemove and is recommended when your data
set is more than a few files large. `Hashfiles` are also reusable,
allowing you to further reduce the amount of hashing done on subsequent
dedupe runs.

    If `hashfile` does not exist it will be created. If it exists,
`duperemove` will check the file paths stored inside of it for changes.
Files which have changed will be rescanned and their updated hashes will be
written to the `hashfile`. Deleted files will be removed from the `hashfile`.

    New files are only added to the `hashfile` if they are discoverable via
the `files` argument. For that reason you probably want to provide the
same `files` list and `-r` arguments on each run of
`duperemove`.  The file discovery algorithm is efficient and will only
visit each file once, even if it is already in the `hashfile`.

    Adding a new path to a hashfile is as simple as adding it to the `files`
argument.

    When deduping from a hashfile, duperemove will avoid deduping files which
have not changed since the last dedupe.

**-B** `N`, **\--batchsize**=`N`
  ~ Run the deduplication phase every `N` files newly scanned. This greatly reduces
memory usage for large dataset, or when you are doing partial extents lookup,
but reduces multithreading efficiency.

    Because of that small overhead, its value shall be selected based
on the average file size and `blocksize`.

    `1000` is a sane value for
extents-only lookups, while you can go as low as `1` if you are
running `duperemove` on very large files (like virtual machines etc).

    By default, batching is disabled.

**-h**
  ~ Print numbers in human-readable format.

**-q**
  ~ Quiet mode. Duperemove will only print errors and a short summary of
any dedupe.

**-v**
  ~ Be verbose.

**\--help**
  ~ Prints help text.

## Advanced options

**-A**
  ~ Opens files readonly when deduping. Primarily for use by privileged
users on readonly snapshots. Disabled by default.

**\--fdupes**
  ~ Run in `fdupes` mode. With this option you can pipe the output of
`fdupes` to duperemove to dedupe any duplicate files found. When
receiving a file list in this manner, duperemove will skip the hashing phase.

**-L**
  ~ Print all files in the hashfile and exit. Requires the `--hashfile` option.
Will print additional information about each file when run with `-v`.

**-R** `file`
  ~ Remove file from the db and exit. Can be specified multiple
times. Duperemove will read the list from standard input if a hyphen
(-) is provided. Requires the `--hashfile` option.

    `Note:` If you are piping filenames from another duperemove instance it
is advisable to do so into a temporary file first as running duperemove
simultaneously on the same hashfile may corrupt that hashfile.

**\--skip-zeroes**
  ~ Read data blocks and skip any zeroed blocks, useful for speedup duperemove,
but can prevent deduplication of zeroed files.

**-b** `size`
  ~ Use the specified block size for reading file extents. Defaults to 128K.

**\--io-threads**=`N`
  ~ Use N threads for I/O. This is used by the file hashing and dedupe
stages. Default is automatically detected based on number of
host cpus.

**\--cpu-threads**=`N`
  ~ Use N threads for CPU bound tasks. This is used by the duplicate
extent finding stage. Default is automatically detected based on
number of host cpus.

    `Note:` Hyperthreading can adversely affect performance of the
extent finding stage. If duperemove detects an Intel CPU with
hyperthreading it will use half the number of cores reported by the
system for cpu bound tasks.

**\--dedupe-options**=`options`
  ~ Comma separated list of options which alter how we dedupe. Prepend 'no' to an
option in order to turn it off.

    **[no]partial**
    ~ Duperemove can often find more dedupe by comparing portions of extents
to each other. This can be a lengthy, CPU intensive task so it is
turned off by default. Using `--batchsize` is recommended to
limit the negative effects of this option.

        The code behind this option is under active development and as a
result the semantics of the `partial` argument may change.

    **[no]same**
    ~ Defaults to `off`. Allow dedupe of extents within the same
file.

    **[no]fiemap**
    ~ Defaults to `on`. Duperemove uses the `fiemap` ioctl during
the dedupe stage to optimize out already deduped extents as well as to
provide an estimate of the space saved after dedupe operations are
complete.

        Unfortunately, some versions of Btrfs exhibit extremely poor
performance in fiemap as the number of references on a file extent
goes up. If you are experiencing the dedupe phase slowing down
or 'locking up' this option may give you a significant amount of
performance back.

        `Note:` This does not turn off all usage of fiemap, to disable
fiemap during the file scan stage, you will also want to use the
`--lookup-extents=no` option.

    **[no]block**
    ~ Deprecated.

**\--lookup-extents**={yes|no}
  ~ Defaults to `yes`. Allows duperemove to skip checksumming some blocks by
checking their extent state.

**\--read-hashes**=`hashfile`
  ~ **This option is primarily for testing**. See the `--hashfile` option if you want to use hashfiles.

    Read hashes from a hashfile. A file list is not required with this
option. Dedupe can be done if duperemove is run from the same base
directory as is stored in the hash file (basically duperemove has to
be able to find the files).

**\--write-hashes**=`hashfile`
  ~ **This option is primarily for testing**. See the `--hashfile` option if you want to use hashfiles.

    Write hashes to a hashfile. These can be read in at a later date and
deduped from.

**\--debug**
  ~ Print debug messages, forces `-v` if selected.

**\--hash-threads**=`N`
  ~ Deprecated, see `--io-threads` above.

**\--exclude**=`PATTERN`
  ~ You an exclude certain files and folders from the deduplication process. This
might be benefical for skipping subvolume snapshot mounts, for instance. You
need to provide full path for exclusion. For example providing just a file name
with a wildcard i.e `duperemove --exclude file-*` won't ever match because internally
duperemove works with absolute paths. Another thing to keep in mind is that
shells usually expand glob pattern so the passed in pattern ought to also be
quoted. Taking everything into consideration the correct way to pass an exclusion
pattern is `duperemove --exclude "/path/to/dir/file*" /path/to/dir`

# EXAMPLES

## Simple Usage

Dedupe the files in directory /foo, recurse into all subdirectories. You only want to use this for small data sets:

	duperemove -dr /foo

Use duperemove with fdupes to dedupe identical files below directory foo:

	fdupes -r /foo | duperemove --fdupes

## Using Hashfiles
Duperemove can optionally store the hashes it calculates in a
hashfile. Hashfiles have two primary advantages - memory usage and
re-usability. When using a hashfile, duperemove will stream computed
hashes to it, instead of main memory.

If Duperemove is run with an existing hashfile, it will only scan
those files which have changed since the last time the hashfile was
updated. The `files` argument controls which directories
duperemove will scan for newly added files. In the simplest usage, you
rerun duperemove with the same parameters and it will only scan
changed or newly added files - see the first example below.

Dedupe the files in directory foo, storing hashes in foo.hash. We can
run this command multiple times and duperemove will only checksum and
dedupe changed or newly added files:

	duperemove -dr --hashfile=foo.hash foo/

Don't scan for new files, only update changed or deleted files, then dedupe:

	duperemove -dr --hashfile=foo.hash

Add directory bar to our hashfile and discover any files that were
recently added to foo:

	duperemove -dr --hashfile=foo.hash foo/ bar/

List the files tracked by foo.hash:

	duperemove -L --hashfile=foo.hash

# FAQ

## Is duperemove safe for my data?

Yes. To be specific, duperemove does not deduplicate the data itself.
It simply finds candidates for dedupe and submits them to the Linux
kernel FIDEDUPERANGE ioctl. In order to ensure data integrity, the
kernel locks out other access to the file and does a byte-by-byte
compare before proceeding with the dedupe.

## Is is safe to interrupt the program (Ctrl-C)?

Yes. The Linux kernel deals with the actual data. On Duperemove' side,
a transactional database engine is used. The result is that you
should be able to ctrl-c the program at any point and re-run without
experiencing corruption of your hashfile. In case of a bug, your hashfile
may be broken, but your data never will.

## I got two identical files, why are they not deduped?

Duperemove by default works on extent granularity. What this means is if there
are two files which are logically identical (have the same content) but are
laid out on disk with different extent structure they won't be deduped. For
example if 2 files are 128k each and their content are identical but one of
them consists of a single 128k extent and the other of 2 * 64k extents then
they won't be deduped. This behavior is dependent on the current implementation
and is subject to change as duperemove is being improved.

## What is the cost of deduplication?

Deduplication will lead to increased fragmentation. The blocksize
chosen can have an effect on this. Larger blocksizes will fragment
less but may not save you as much space. Conversely, smaller block
sizes may save more space at the cost of increased fragmentation.

## How can I find out my space savings after a dedupe?

Duperemove will print out an estimate of the saved space after a
dedupe operation for you.

You can get a more accurate picture by running 'btrfs fi df' before
and after each duperemove run.

Be careful about using the 'df' tool on btrfs - it is common for space
reporting to be 'behind' while delayed updates get processed, so an
immediate df after deduping might not show any savings.

## Why is the total deduped data report an estimate?

At the moment duperemove can detect that some underlying extents are
shared with other files, but it can not resolve which files those
extents are shared with.

Imagine duperemove is examining a series of files and it notes a shared
data region in one of them. That data could be shared with a file
outside of the series. Since duperemove can't resolve that information
it will account the shared data against our dedupe operation while in
reality, the kernel might deduplicate it further for us.

## Why are my files showing dedupe but my disk space is not shrinking?

This is a little complicated, but it comes down to a feature in Btrfs
called _bookending_. The [Btrfs wiki](http://en.wikipedia.org/wiki/Btrfs#Extents)
explains this in detail.

Essentially though, the underlying representation of an extent in
Btrfs can not be split (with small exception). So sometimes we can end
up in a situation where a file extent gets partially deduped (and the
extents marked as shared) but the underlying extent item is not freed
or truncated.

## Is there an upper limit to the amount of data duperemove can process?

Duperemove is fast at reading and cataloging data. Dedupe runs will be
memory limited unless the `--hashfile` option is used. `--hashfile` allows
duperemove to temporarily store duplicated hashes to disk, thus removing the
large memory overhead and allowing for a far larger amount of data to be
scanned and deduped. Realistically though you will be limited by the speed of
your disks and cpu. In those situations where resources are limited you may
have success by breaking up the input data set into smaller pieces.

When using a hashfile, duperemove will only store duplicate hashes in
memory. During normal operation then the hash tree will make up the
largest portion of duperemove memory usage. As of Duperemove v0.11
hash entries are 88 bytes in size. If you know the number of duplicate
blocks in your data set you can get a rough approximation of memory
usage by multiplying with the hash entry size.

Actual performance numbers are dependent on hardware - up to date
testing information is kept on the duperemove wiki (see below for the link).

## How large of a hashfile will duperemove create?

Hashfiles are essentially sqlite3 database files with several tables,
the largest of which are the files and extents tables. Each extents
table entry is about 72 bytes though that may grow as features are
added. The size of a files table entry depends on the file path but a
good estimate is around 270 bytes per file. The number of extents in a
data set is directly proportional to file fragmentation level.

If you know the total number of extents and files in your data set then
you can calculate the hashfile size as:

	Hashfile Size = Num Hashes * 72 + Num Files * 270

Using a real world example of 1TB (8388608 128K blocks) of data over 1000 files:

	8388608 * 72 + 270 * 1000 = 755244720 or about 720MB for 1TB spread over 1000 files.

`Note that none of this takes database overhead into account.`

# NOTES
Deduplication is currently only supported by the `btrfs` and `xfs` filesystem.

The Duperemove project page can be found on [github](https://github.com/markfasheh/duperemove)

There is also a [wiki](https://github.com/markfasheh/duperemove/wiki)

# SEE ALSO
* `hashstats(8)`
* `filesystems(5)`
* `btrfs(8)`
* `xfs(8)`
* `fdupes(1)`
* `ioctl_fideduprange(2)`
