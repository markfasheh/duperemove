# Duperemove: Frequently Asked Questions

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
up in a situation where a file extent gets partially deduped (and the
extents marked as shared) but the underlying extent item is not freed
or truncated.
