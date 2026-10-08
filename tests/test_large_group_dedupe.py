#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Regression for duperemove issue #392, using real files and dedupe ioctls.

Adapted from Martin Leitner-Ankerl's regression test in oans PR #218:
https://github.com/martinus/oans/commit/12849ff92b170b927edfa7ade6f90db43c1f06e5
The standalone runner and the additional missing-file case are by Jeffrey Wall.
"""

import errno
import fcntl
import os
import resource
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

# Linux UAPI: linux/fs.h and linux/fiemap.h. Checking physical mappings proves
# that a successful exit actually deduped the readable files.
FICLONE = 0x40049409
FS_IOC_FIEMAP = 0xC020660B
FIEMAP_FLAG_SYNC = 1
FIEMAP_EXTENT_LAST = 1
SIZE = 64 << 10
DATA = bytes(range(256)) * (SIZE // 256)
BINARY = (
    Path(sys.argv.pop(1)).resolve()
    if len(sys.argv) > 1
    else Path("./duperemove").resolve()
)


def extents(path):
    capacity = 16
    buffer = bytearray(32 + capacity * 56)
    struct.pack_into("=QQIIII", buffer, 0, 0, SIZE, FIEMAP_FLAG_SYNC, 0, capacity, 0)
    with path.open("rb") as file:
        fcntl.ioctl(file.fileno(), FS_IOC_FIEMAP, buffer, True)
    count = struct.unpack_from("=I", buffer, 20)[0]
    if (
        not count
        or not struct.unpack_from("=I", buffer, 32 + (count - 1) * 56 + 40)[0]
        & FIEMAP_EXTENT_LAST
    ):
        raise AssertionError("FIEMAP did not return the complete file mapping")
    return [struct.unpack_from("=QQQ", buffer, 32 + i * 56) for i in range(count)]


@unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux dedupe ioctls")
@unittest.skipIf(os.geteuid() == 0, "root can open the unreadable candidate")
class LargeGroupDedupeTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="duperemove-392-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        source = self.work / "probe-source"
        source.write_bytes(DATA)
        with source.open("rb") as src, (self.work / "probe-clone").open("wb") as dst:
            try:
                fcntl.ioctl(dst.fileno(), FICLONE, src.fileno())
            except OSError as error:
                if error.errno in (errno.EOPNOTSUPP, errno.ENOTTY, errno.EINVAL):
                    self.skipTest(
                        "set TMPDIR to a reflink-capable XFS or Btrfs filesystem"
                    )
                raise

    def run_duperemove(self, *arguments):
        result = subprocess.run(
            [str(BINARY), "-q", "--io-threads=1", "--cpu-threads=1", *arguments],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        return result

    def exercise_group(self, count, skipped, missing=False):
        tree = self.work / f"group-{count}-{skipped}-{missing}"
        tree.mkdir()
        files = [tree / f"file-{i:03d}" for i in range(count)]
        for path in files:
            path.write_bytes(DATA)
        initial = [extents(path) for path in files]
        self.assertEqual(count, len({mapping[0][1] for mapping in initial}))
        hashfile = tree.with_suffix(".hash")
        self.run_duperemove("-r", f"--hashfile={hashfile}", str(tree))

        # Hash completion determines ids; select the tail of the stored group
        # rather than assuming a filename corresponds to its last member.
        with closing(sqlite3.connect(hashfile)) as database:
            victims = [
                Path(row[0])
                for row in database.execute(
                    "select filename from files order by id desc limit ?", (skipped,)
                )
            ]
        self.assertEqual(skipped, len(victims))
        try:
            for victim in victims:
                if missing:
                    victim.unlink()
                else:
                    victim.chmod(0)

            # Reading saved hashes avoids rescanning away the skipped candidates.
            result = self.run_duperemove("-d", f"--read-hashes={hashfile}")
            for victim in victims:
                self.assertIn(f"{victim}: Skipping dedupe.", result.stderr)
            readable = [path for path in files if path not in victims]
            mapping = extents(readable[0])
            for path in readable:
                self.assertEqual(mapping, extents(path), f"{path} was not deduped")
                self.assertEqual(DATA, path.read_bytes())
        finally:
            if not missing:
                for victim in victims:
                    victim.chmod(0o644)
        if not missing:
            for victim in victims:
                self.assertEqual(DATA, victim.read_bytes())
                self.assertNotEqual(mapping, extents(victim))

    def test_unreadable_tail_at_batch_boundary(self):
        # Neighboring group sizes are controls: only a tail skipped before the
        # next context is allocated used to leave the reopened source behind.
        for count, skipped in ((120, 1), (121, 1), (122, 1), (122, 2)):
            with self.subTest(count=count, skipped=skipped):
                self.exercise_group(count, skipped)

    def test_missing_tail_at_batch_boundary(self):
        # A pair of missing destinations matches the independently observed
        # failure on an Ubuntu XFS runner, rather than only the chmod reproducer.
        self.exercise_group(122, 2, missing=True)


if __name__ == "__main__":
    # The unpatched binary intentionally aborts; retain the test's diagnostics
    # without creating core files on the machine running the regression.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    unittest.main(verbosity=2)
