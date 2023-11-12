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
Count the sum of bytes shared in a file.

An extent is reported as shared if it has more than one reference.

# SEE ALSO

* `filefrag(8)`
