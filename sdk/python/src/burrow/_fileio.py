"""`sandbox.open`: builtin `open()` over the `Fs` handle calls.

Built the way CPython builds `open()`: a raw file over the handle, wrapped in
the stdlib's own buffered and text layers. Readline, iteration, newline
translation, seeking a text file and the errors for a misused mode are then the
stdlib's code rather than a copy of it.
"""

from __future__ import annotations

import errno
import io
import os
import warnings
from typing import TYPE_CHECKING, Any, Optional

from ._os import fspath, to_stat_result
from ._pb import api_pb2

if TYPE_CHECKING:
    from .sandbox import Sandbox

# open(2) flags in their Linux values, which is what the guest is. This
# machine's `os.O_*` are not: O_CREAT is 0o1000 on macOS.
O_RDONLY = 0
O_WRONLY = 1
O_RDWR = 2
O_CREAT = 0o100
O_EXCL = 0o200
O_TRUNC = 0o1000
O_APPEND = 0o2000

# The most one read or write call carries.
_CHUNK = 4 * 1024 * 1024

# What `buffering=-1` gives a file. CPython takes the file's st_blksize, a few
# KiB; here every refill is a round trip to the guest, so fewer of them is
# worth more than the memory.
_BUFFER_SIZE = 1024 * 1024


class FileIO(io.RawIOBase):
    """The raw file under what `sandbox.open` returns, as `io.FileIO` is under
    what `open` does.

    The position is kept here rather than in the guest: every read and write
    names where it goes, since there is no seek call to move the guest's.
    """

    def __init__(
        self,
        sandbox: "Sandbox",
        name: Any,
        mode: str,
        handle: int,
        readable: bool,
        writable: bool,
        appending: bool,
    ):
        super().__init__()
        self._sandbox = sandbox
        self.name = name
        self.mode = mode
        self._handle = handle
        self._readable = readable
        self._writable = writable
        self._appending = appending
        # None once an append has moved it to wherever the end now is, which
        # only the guest knows. Read back the next time it is needed.
        self._pos: Optional[int] = None if appending else 0

    def _check_closed(self) -> None:
        if self.closed:
            raise ValueError("I/O operation on closed file")

    def readable(self) -> bool:
        self._check_closed()
        return self._readable

    def writable(self) -> bool:
        self._check_closed()
        return self._writable

    def seekable(self) -> bool:
        self._check_closed()
        return True

    def fileno(self) -> int:
        # No number would be honest: a handle is not a descriptor on this
        # machine, and code that passed one to a local syscall (os.fstat to
        # size a request body, say) would act on whatever file has that
        # number here. BytesIO refuses the same way.
        raise io.UnsupportedOperation("fileno: a sandbox file has no local descriptor")

    def _fstat(self) -> os.stat_result:
        res = self._sandbox._fs(fstat=api_pb2.FsHandle(handle=self._handle))
        return to_stat_result(res.stat)

    def _read(self, length: int) -> bytes:
        self._check_closed()
        if not self._readable:
            raise io.UnsupportedOperation("File not open for reading")
        res = self._sandbox._fs(
            read=api_pb2.FsRead(handle=self._handle, position=self.tell(), length=length)
        )
        self._pos += len(res.data)
        return res.data

    def readinto(self, buffer: Any) -> int:
        with memoryview(buffer) as view, view.cast("B") as target:
            data = self._read(min(len(target), _CHUNK))
            target[: len(data)] = data
        return len(data)

    def readall(self) -> bytes:
        parts = []
        while True:
            data = self._read(_CHUNK)
            if not data:
                return b"".join(parts)
            parts.append(data)

    def write(self, b: Any) -> int:
        self._check_closed()
        if not self._writable:
            raise io.UnsupportedOperation("File not open for writing")
        with memoryview(b) as view, view.cast("B") as source:
            data = source[:_CHUNK].tobytes()
        res = self._sandbox._fs(
            write=api_pb2.FsWrite(
                handle=self._handle,
                # O_APPEND puts every write at the end whatever it names.
                position=-1 if self._appending else self.tell(),
                data=data,
            )
        )
        if self._appending:
            self._pos = None
        else:
            self._pos += res.written
        return res.written

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        self._check_closed()
        if whence == os.SEEK_SET:
            base = 0
        elif whence == os.SEEK_CUR:
            base = self.tell()
        elif whence == os.SEEK_END:
            base = self._fstat().st_size
        else:
            raise ValueError(f"invalid whence ({whence}, should be 0, 1 or 2)")
        if base + offset < 0:
            raise OSError(errno.EINVAL, os.strerror(errno.EINVAL))
        self._pos = base + offset
        return self._pos

    def tell(self) -> int:
        self._check_closed()
        if self._pos is None:
            self._pos = self._fstat().st_size
        return self._pos

    def truncate(self, size: Optional[int] = None) -> int:
        self._check_closed()
        if not self._writable:
            raise io.UnsupportedOperation("File not open for writing")
        if size is None:
            size = self.tell()
        self._sandbox._fs(ftruncate=api_pb2.FsFtruncate(handle=self._handle, length=size))
        return size

    def close(self) -> None:
        if self.closed:
            return
        try:
            self._sandbox._fs(close=api_pb2.FsHandle(handle=self._handle))
        finally:
            super().close()


def open_file(
    sandbox: "Sandbox",
    file: Any,
    mode: str = "r",
    buffering: int = -1,
    encoding: Optional[str] = None,
    errors: Optional[str] = None,
    newline: Optional[str] = None,
) -> Any:
    """`open()`, for a file in the sandbox. The checks and their messages are
    CPython's, in its order."""
    if not isinstance(mode, str):
        raise TypeError(f"open() argument 'mode' must be str, not {type(mode).__name__}")
    path = fspath(file)
    modes = set(mode)
    if modes - set("axrwb+t") or len(mode) > len(modes):
        raise ValueError(f"invalid mode: {mode!r}")
    creating = "x" in modes
    reading = "r" in modes
    writing = "w" in modes
    appending = "a" in modes
    updating = "+" in modes
    text = "t" in modes
    binary = "b" in modes
    if text and binary:
        raise ValueError("can't have text and binary mode at once")
    if creating + reading + writing + appending > 1:
        raise ValueError("must have exactly one of create/read/write/append mode")
    if not (creating or reading or writing or appending):
        raise ValueError(
            "Must have exactly one of create/read/write/append mode and at most one plus"
        )
    if binary and encoding is not None:
        raise ValueError("binary mode doesn't take an encoding argument")
    if binary and errors is not None:
        raise ValueError("binary mode doesn't take an errors argument")
    if binary and newline is not None:
        raise ValueError("binary mode doesn't take a newline argument")
    if binary and buffering == 1:
        warnings.warn(
            "line buffering (buffering=1) isn't supported in binary mode, "
            "the default buffer size will be used",
            RuntimeWarning,
            2,
        )
    # Refused before the file is opened, unlike CPython, which opens it first
    # and so truncates a file it then refuses to write.
    if buffering == 0 and not binary:
        raise ValueError("can't have unbuffered text I/O")

    if reading:
        flags, raw_mode = O_RDONLY, "rb+" if updating else "rb"
    elif writing:
        flags, raw_mode = O_WRONLY | O_CREAT | O_TRUNC, "rb+" if updating else "wb"
    elif creating:
        flags, raw_mode = O_WRONLY | O_CREAT | O_EXCL, "xb+" if updating else "xb"
    else:
        flags, raw_mode = O_WRONLY | O_CREAT | O_APPEND, "ab+" if updating else "ab"
    if updating:
        flags = flags & ~O_WRONLY | O_RDWR

    handle = sandbox._fs(open=api_pb2.FsOpen(path=path, flags=flags, mode=0o666)).handle
    raw = FileIO(
        sandbox,
        os.fspath(file),
        raw_mode,
        handle,
        readable=reading or updating,
        writable=not reading or updating,
        appending=appending,
    )
    try:
        line_buffering = buffering == 1
        if buffering == 1 or buffering < 0:
            buffering = _BUFFER_SIZE
        if buffering == 0:
            return raw
        if updating:
            buffer: Any = io.BufferedRandom(raw, buffering)
        elif reading:
            buffer = io.BufferedReader(raw, buffering)
        else:
            buffer = io.BufferedWriter(raw, buffering)
        if binary:
            return buffer
        # UTF-8 rather than this machine's locale encoding: the file is the
        # guest's, and what this machine's locale says about it is nothing.
        wrapper = io.TextIOWrapper(buffer, encoding or "utf-8", errors, newline, line_buffering)
        wrapper.mode = mode
        return wrapper
    except BaseException:
        raw.close()
        raise
