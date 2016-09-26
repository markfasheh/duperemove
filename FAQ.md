# Duperemove: Frequently Asked Questions

### Is there an upper limit to the amount of data duperemove can process?

Duperemove v0.11 is fast at reading and cataloging data. Dedupe runs
will be memory limited unless the '--hashfile' option is used. '--hashfile'
allows duperemove to temporarily store duplicated hashes to disk, thus removing
the large memory overhead and allowing for a far larger amount of data to be
scanned and deduped. Realistically though you will be limited by the speed of
your disks and cpu.

Actual performance numbers are dependent on hardware - up to date
testing information is kept [on the wiki](https://github.com/markfasheh/duperemove/wiki/Performance-Numbers)


### How can I find out my space savings after a dedupe?

Duperemove will print out an estimate of the saved space after a
dedupe operation for you.

You can get a more accurate picture by running 'btrfs fi df' before
and after each duperemove run.

Be careful about using the 'df' tool on btrfs - it is common for space
reporting to be 'behind' while delayed updates get processed, so an
immediate df after deduping might not show any savings.


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
up in a situation where a file extent gets partially deduped (and the
extents marked as shared) but the underlying extent item is not freed
or truncated.
