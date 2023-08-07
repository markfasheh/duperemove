---
title: btrfs-extent-same
section: 8
header: System Manager’s Manual
footer: btrfs-extent-same
date: March 2014
---
# NAME

`btrfs-extent-same` - directly access the FIDEDUPRANGE ioctl

# SYNOPSIS

**btrfs-extent-same** *extent-len* *file1* *offset1* *file2* *offset2* *[...]*

# DESCRIPTION

`btrfs-extent-same` is a wrapper around the FIDEDUPRANGE ioctl. `extent-len` and all offsets should be specified in bytes.

# SEE ALSO

* `filesystems(5)`
* `btrfs(8)`
* `ioctl_fideduprange(2)`
* `xfs_io(8)`
