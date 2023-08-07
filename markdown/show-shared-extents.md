---
title: show-shared-extents
section: 8
header: System Manager’s Manual 
footer: show-shared-extents
date: December 2014
---
# Name

`show-shared-extents` - Show extents that are shared.

# SYNOPSIS

`show-shared-extents` *files* *...*

# DESCRIPTION
Print all the extents in `files` that are shared. A sum of shared
extents is also printed.

On btrfs, an extent is reported as shared if it has more than one reference.

# SEE ALSO

* `duperemove(8)`
* `btrfs(8)`
