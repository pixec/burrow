"""`sandbox.os` and `sandbox.os.path`: the stdlib's functions, against the
sandbox's filesystem.

Each is one `Fs` call, or the few the stdlib's own definition takes, and fails
the way the stdlib does: a kernel error is raised as the `OSError` subclass its
errno names, with the path or paths it was about.
"""

from __future__ import annotations

import errno as _errno
import math
import os
import posixpath
import stat as _stat
import time
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional

from ._pb import api_pb2

if TYPE_CHECKING:
    from .sandbox import Sandbox


def fspath(path: Any) -> str:
    """A path argument as the wire carries it. Takes what the stdlib takes:
    str, bytes, or anything with `__fspath__`."""
    return os.fsdecode(path)


def os_error(err: api_pb2.FsError) -> OSError:
    """The exception the stdlib raises for a failed call.

    The guest reports a Linux errno, and this machine's numbers can differ
    (ENOTEMPTY is 39 on Linux and 66 on macOS), so it is looked up again by
    name: `OSError` picks its subclass from the number, and only this
    platform's number picks the right one. An errno this platform has no name
    for keeps the guest's number.
    """
    number = getattr(_errno, err.code, err.errno)
    args: List[Any] = [number, os.strerror(number), err.path or None]
    if err.dest:
        # The fourth argument is Windows' own error code, ignored elsewhere.
        args += [None, err.dest]
    return OSError(*args)


# `os.stat_result` takes its first ten fields by position and the rest by
# name, and which names exist depends on the platform: st_birthtime is
# macOS and BSD only. Python 3.14 refuses a name it does not have.
_STAT_FIELDS = frozenset(name for name in dir(os.stat_result) if name.startswith("st_"))


def _seconds(ns: int) -> float:
    whole, rest = divmod(ns, 10**9)
    return whole + rest * 1e-9


def to_stat_result(raw: api_pb2.FsStatResult) -> os.stat_result:
    times = (raw.atime_ns, raw.mtime_ns, raw.ctime_ns)
    named = {
        "st_atime": _seconds(raw.atime_ns),
        "st_mtime": _seconds(raw.mtime_ns),
        "st_ctime": _seconds(raw.ctime_ns),
        "st_atime_ns": raw.atime_ns,
        "st_mtime_ns": raw.mtime_ns,
        "st_ctime_ns": raw.ctime_ns,
        "st_blksize": raw.blksize,
        "st_blocks": raw.blocks,
        "st_rdev": raw.rdev,
    }
    if raw.birthtime_ns:
        named["st_birthtime"] = _seconds(raw.birthtime_ns)
        named["st_birthtime_ns"] = raw.birthtime_ns
    return os.stat_result(
        (
            raw.mode,
            raw.ino,
            raw.dev,
            raw.nlink,
            raw.uid,
            raw.gid,
            raw.size,
            *(ns // 10**9 for ns in times),
        ),
        {name: value for name, value in named.items() if name in _STAT_FIELDS},
    )


def _to_ns(seconds: float) -> int:
    whole = math.floor(seconds)
    return int(whole) * 10**9 + math.floor((seconds - whole) * 1e9)


class DirEntry:
    """What `scandir` yields, as `os.DirEntry`.

    The listing carries each entry's type, so `is_dir`, `is_file` and
    `is_symlink` cost nothing for anything but a symlink being followed.
    `stat` and `inode` make a call the first time and keep the answer.
    """

    def __init__(self, os_: "SandboxOs", top: str, name: str, kind: str):
        self._os = os_
        self.name = name
        self.path = posixpath.join(top, name)
        self._kind = kind
        self._stat: Optional[os.stat_result] = None
        self._lstat: Optional[os.stat_result] = None

    def __fspath__(self) -> str:
        return self.path

    def __repr__(self) -> str:
        return f"<DirEntry {self.name!r}>"

    def inode(self) -> int:
        return self.stat(follow_symlinks=False).st_ino

    def is_symlink(self) -> bool:
        if self._kind == "unknown":
            return _stat.S_ISLNK(self.stat(follow_symlinks=False).st_mode)
        return self._kind == "symlink"

    def is_dir(self, *, follow_symlinks: bool = True) -> bool:
        return self._test(follow_symlinks, _stat.S_IFDIR, "dir")

    def is_file(self, *, follow_symlinks: bool = True) -> bool:
        return self._test(follow_symlinks, _stat.S_IFREG, "file")

    def _test(self, follow_symlinks: bool, mode: int, kind: str) -> bool:
        if self._kind == "unknown" or (follow_symlinks and self._kind == "symlink"):
            try:
                st = self.stat(follow_symlinks=follow_symlinks)
            except FileNotFoundError:
                return False
            return _stat.S_IFMT(st.st_mode) == mode
        return self._kind == kind

    def stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
        if follow_symlinks and self.is_symlink():
            if self._stat is None:
                self._stat = self._os.stat(self.path)
            return self._stat
        if self._lstat is None:
            self._lstat = self._os.lstat(self.path)
        return self._lstat


class _ScandirIterator:
    """`scandir`'s iterator, which is also a context manager. The listing
    arrives whole, so closing it early only stops the iteration."""

    def __init__(self, entries: Iterator[DirEntry]):
        self._entries = entries

    def __iter__(self) -> "_ScandirIterator":
        return self

    def __next__(self) -> DirEntry:
        return next(self._entries)

    def close(self) -> None:
        self._entries = iter(())

    def __enter__(self) -> "_ScandirIterator":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class SandboxOsPath:
    """`os.path`, with every question that touches the filesystem asked of the
    sandbox. The pure string functions are `posixpath`'s own, since the guest
    is Linux whatever this machine is."""

    sep = posixpath.sep
    curdir = posixpath.curdir
    pardir = posixpath.pardir
    extsep = posixpath.extsep
    altsep = posixpath.altsep
    pathsep = posixpath.pathsep
    devnull = posixpath.devnull

    basename = staticmethod(posixpath.basename)
    commonpath = staticmethod(posixpath.commonpath)
    commonprefix = staticmethod(posixpath.commonprefix)
    dirname = staticmethod(posixpath.dirname)
    isabs = staticmethod(posixpath.isabs)
    join = staticmethod(posixpath.join)
    normcase = staticmethod(posixpath.normcase)
    normpath = staticmethod(posixpath.normpath)
    samestat = staticmethod(posixpath.samestat)
    split = staticmethod(posixpath.split)
    splitdrive = staticmethod(posixpath.splitdrive)
    splitext = staticmethod(posixpath.splitext)

    def __init__(self, os_: "SandboxOs"):
        self._os = os_

    def exists(self, path: Any) -> bool:
        try:
            self._os.stat(path)
        except (OSError, ValueError):
            return False
        return True

    def lexists(self, path: Any) -> bool:
        try:
            self._os.lstat(path)
        except (OSError, ValueError):
            return False
        return True

    def _mode(self, path: Any, follow_symlinks: bool = True) -> int:
        try:
            return self._os.stat(path, follow_symlinks=follow_symlinks).st_mode
        except (OSError, ValueError):
            return 0

    def isfile(self, path: Any) -> bool:
        return _stat.S_ISREG(self._mode(path))

    def isdir(self, s: Any) -> bool:
        return _stat.S_ISDIR(self._mode(s))

    def islink(self, path: Any) -> bool:
        return _stat.S_ISLNK(self._mode(path, follow_symlinks=False))

    def getsize(self, filename: Any) -> int:
        return self._os.stat(filename).st_size

    def getmtime(self, filename: Any) -> float:
        return self._os.stat(filename).st_mtime

    def getatime(self, filename: Any) -> float:
        return self._os.stat(filename).st_atime

    def getctime(self, filename: Any) -> float:
        return self._os.stat(filename).st_ctime

    def samefile(self, f1: Any, f2: Any) -> bool:
        return posixpath.samestat(self._os.stat(f1), self._os.stat(f2))

    def realpath(self, filename: Any, *, strict: bool = False) -> str:
        path = fspath(filename)
        try:
            return self._os._sandbox._fs(realpath=api_pb2.FsRealpath(path=path)).path
        except OSError:
            head, tail = posixpath.split(path.rstrip("/"))
            if strict or not tail:
                raise
        # Without strict the stdlib resolves what exists and appends the rest
        # as written. Nothing past a missing component can be a symlink, so
        # normalising that part is all resolving it would do.
        return posixpath.normpath(posixpath.join(self.realpath(head or "."), tail))


class SandboxOs:
    """`os`, for the sandbox's filesystem.

    Paths are the guest's: absolute, or relative to the guest agent's working
    directory. Signatures, defaults and exceptions are the stdlib's; `dir_fd`
    is not taken, since there is no descriptor here to be relative to.
    """

    F_OK = 0
    X_OK = 1
    W_OK = 2
    R_OK = 4

    sep = posixpath.sep
    curdir = posixpath.curdir
    pardir = posixpath.pardir
    extsep = posixpath.extsep
    altsep = posixpath.altsep
    pathsep = posixpath.pathsep
    linesep = "\n"
    devnull = posixpath.devnull

    fspath = staticmethod(os.fspath)

    def __init__(self, sandbox: "Sandbox"):
        self._sandbox = sandbox
        self.path = SandboxOsPath(self)

    def _fs(self, **op: Any) -> api_pb2.FsResponse:
        return self._sandbox._fs(**op)

    def stat(self, path: Any, *, follow_symlinks: bool = True) -> os.stat_result:
        res = self._fs(stat=api_pb2.FsStat(path=fspath(path), is_nofollow=not follow_symlinks))
        return to_stat_result(res.stat)

    def lstat(self, path: Any) -> os.stat_result:
        return self.stat(path, follow_symlinks=False)

    def listdir(self, path: Any = ".") -> List[str]:
        res = self._fs(read_dir=api_pb2.FsReadDir(path=fspath(path)))
        return [entry.name for entry in res.entries.entries]

    def scandir(self, path: Any = ".") -> _ScandirIterator:
        top = fspath(path)
        res = self._fs(read_dir=api_pb2.FsReadDir(path=top))
        return _ScandirIterator(
            DirEntry(self, top, entry.name, entry.type) for entry in res.entries.entries
        )

    def walk(
        self,
        top: Any,
        topdown: bool = True,
        onerror: Any = None,
        followlinks: bool = False,
    ) -> Iterator[Any]:
        """`os.walk`. One listing per directory: the listing says which
        entries are symlinks, so deciding whether to descend costs no call of
        its own unless the caller added a name to `dirs`."""
        stack: List[Any] = [fspath(top)]
        while stack:
            top = stack.pop()
            if isinstance(top, tuple):
                yield top
                continue
            dirs: List[str] = []
            nondirs: List[str] = []
            # Whether each directory listed is a symlink to one.
            links: Dict[str, bool] = {}
            walk_dirs: List[str] = []
            try:
                entries = list(self.scandir(top))
            except OSError as error:
                if onerror is not None:
                    onerror(error)
                continue
            for entry in entries:
                try:
                    is_dir = entry.is_dir()
                except OSError:
                    is_dir = False
                if not is_dir:
                    nondirs.append(entry.name)
                    continue
                dirs.append(entry.name)
                links[entry.name] = entry.is_symlink()
                if not topdown and (followlinks or not links[entry.name]):
                    walk_dirs.append(entry.path)
            if topdown:
                yield top, dirs, nondirs
                for dirname in reversed(dirs):
                    new_path = posixpath.join(top, dirname)
                    if (
                        followlinks
                        or not links.get(dirname, True)
                        or (dirname not in links and not self.path.islink(new_path))
                    ):
                        stack.append(new_path)
            else:
                stack.append((top, dirs, nondirs))
                stack.extend(reversed(walk_dirs))

    def mkdir(self, path: Any, mode: int = 0o777) -> None:
        self._fs(mkdir=api_pb2.FsMkdir(path=fspath(path), mode=mode))

    def makedirs(self, name: Any, mode: int = 0o777, exist_ok: bool = False) -> None:
        path = fspath(name)
        head, tail = posixpath.split(path)
        if not tail:
            head, tail = posixpath.split(head)
        try:
            try:
                self.mkdir(path, mode)
            except FileNotFoundError:
                if not (head and tail):
                    raise
                # Every missing parent in one call, with the default mode the
                # stdlib gives them; only the leaf gets `mode`.
                self._fs(mkdir=api_pb2.FsMkdir(path=head, is_recursive=True))
                self.mkdir(path, mode)
        except OSError:
            if not exist_ok or not self.path.isdir(path):
                raise

    def remove(self, path: Any) -> None:
        self._fs(remove=api_pb2.FsRemove(path=fspath(path)))

    unlink = remove

    def rmdir(self, path: Any) -> None:
        self._fs(remove=api_pb2.FsRemove(path=fspath(path), is_dir_only=True))

    def removedirs(self, name: Any) -> None:
        self.rmdir(name)
        head, tail = posixpath.split(fspath(name))
        if not tail:
            head, tail = posixpath.split(head)
        while head and tail:
            try:
                self.rmdir(head)
            except OSError:
                break
            head, tail = posixpath.split(head)

    def rename(self, src: Any, dst: Any) -> None:
        self._fs(rename=api_pb2.FsRename(src=fspath(src), dst=fspath(dst)))

    # rename(2) already replaces on Linux; the stdlib has both names because
    # Windows' rename does not.
    replace = rename

    def chmod(self, path: Any, mode: int) -> None:
        self._fs(chmod=api_pb2.FsChmod(path=fspath(path), mode=mode))

    def chown(self, path: Any, uid: int, gid: int, *, follow_symlinks: bool = True) -> None:
        self._fs(
            chown=api_pb2.FsChown(
                path=fspath(path), uid=uid, gid=gid, is_nofollow=not follow_symlinks
            )
        )

    def lchown(self, path: Any, uid: int, gid: int) -> None:
        self.chown(path, uid, gid, follow_symlinks=False)

    def link(self, src: Any, dst: Any) -> None:
        self._fs(link=api_pb2.FsLink(existing=fspath(src), path=fspath(dst)))

    def symlink(self, src: Any, dst: Any, target_is_directory: bool = False) -> None:
        self._fs(symlink=api_pb2.FsSymlink(target=fspath(src), path=fspath(dst)))

    def readlink(self, path: Any) -> str:
        return self._fs(readlink=api_pb2.FsReadlink(path=fspath(path))).path

    def utime(
        self,
        path: Any,
        times: Optional[Any] = None,
        *,
        ns: Optional[Any] = None,
        follow_symlinks: bool = True,
    ) -> None:
        """`os.utime`. With neither `times` nor `ns`, now is read from this
        machine's clock rather than the guest's: the call has no way to say
        "now" and let the guest fill it in."""
        if times is not None and ns is not None:
            raise ValueError("utime: you may specify either 'times' or 'ns' but not both")
        if times is not None:
            if not isinstance(times, tuple) or len(times) != 2:
                raise TypeError("utime: 'times' must be either a tuple of two ints or None")
            atime_ns, mtime_ns = (_to_ns(t) for t in times)
        elif ns is not None:
            if not isinstance(ns, tuple) or len(ns) != 2:
                raise TypeError("utime: 'ns' must be a tuple of two ints")
            atime_ns, mtime_ns = ns
        else:
            atime_ns = mtime_ns = time.time_ns()
        self._fs(
            utimes=api_pb2.FsUtimes(
                path=fspath(path),
                atime_ns=atime_ns,
                mtime_ns=mtime_ns,
                is_nofollow=not follow_symlinks,
            )
        )

    def truncate(self, path: Any, length: int) -> None:
        self._fs(truncate=api_pb2.FsTruncate(path=fspath(path), length=length))

    def access(self, path: Any, mode: int) -> bool:
        try:
            self._fs(access=api_pb2.FsAccess(path=fspath(path), mode=mode))
        except OSError:
            return False
        return True
