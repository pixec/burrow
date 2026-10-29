"""`sandbox.Path`: `pathlib`'s concrete path, for the sandbox's filesystem."""

from __future__ import annotations

import posixpath
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any, Iterator, Optional

from ._fileio import O_CREAT, O_EXCL, O_WRONLY
from ._pb import api_pb2

if TYPE_CHECKING:
    from .sandbox import Sandbox


class SandboxPath(PurePosixPath):
    """A path in one sandbox, with `pathlib.Path`'s methods.

    Each sandbox handle has its own subclass, `sandbox.Path`, with the handle
    on the class rather than the instance: every pure operation (`/`,
    `parent`, `with_suffix`, ...) builds its result from the class, so the
    result is bound to the same sandbox on every Python this supports.

    It is still an `os.PathLike`, so handing one to the local `open()` opens a
    local file of that name, not the sandbox's.
    """

    __slots__ = ()
    _sandbox: "Sandbox"

    def stat(self, *, follow_symlinks: bool = True) -> Any:
        return self._sandbox.os.stat(self, follow_symlinks=follow_symlinks)

    def lstat(self) -> Any:
        return self._sandbox.os.lstat(self)

    def exists(self, *, follow_symlinks: bool = True) -> bool:
        if follow_symlinks:
            return self._sandbox.os.path.exists(self)
        return self._sandbox.os.path.lexists(self)

    def is_dir(self) -> bool:
        return self._sandbox.os.path.isdir(self)

    def is_file(self) -> bool:
        return self._sandbox.os.path.isfile(self)

    def is_symlink(self) -> bool:
        return self._sandbox.os.path.islink(self)

    def samefile(self, other_path: Any) -> bool:
        # The other path is read in this sandbox even when it is some other
        # kind of path; pathlib would call its own stat(), which for a local
        # Path means this machine's filesystem.
        return posixpath.samestat(self.stat(), self._sandbox.os.stat(other_path))

    def open(
        self,
        mode: str = "r",
        buffering: int = -1,
        encoding: Optional[str] = None,
        errors: Optional[str] = None,
        newline: Optional[str] = None,
    ) -> Any:
        return self._sandbox.open(self, mode, buffering, encoding, errors, newline)

    def read_bytes(self) -> bytes:
        with self.open(mode="rb") as f:
            return f.read()

    def read_text(
        self,
        encoding: Optional[str] = None,
        errors: Optional[str] = None,
        newline: Optional[str] = None,
    ) -> str:
        with self.open(mode="r", encoding=encoding, errors=errors, newline=newline) as f:
            return f.read()

    def write_bytes(self, data: Any) -> int:
        view = memoryview(data)
        with self.open(mode="wb") as f:
            return f.write(view)

    def write_text(
        self,
        data: str,
        encoding: Optional[str] = None,
        errors: Optional[str] = None,
        newline: Optional[str] = None,
    ) -> int:
        if not isinstance(data, str):
            raise TypeError(f"data must be str, not {data.__class__.__name__}")
        with self.open(mode="w", encoding=encoding, errors=errors, newline=newline) as f:
            return f.write(data)

    def iterdir(self) -> Iterator["SandboxPath"]:
        # Listed when called, as pathlib does since 3.13, so a missing
        # directory raises here rather than at the first next().
        return iter([self / name for name in self._sandbox.os.listdir(self)])

    def mkdir(self, mode: int = 0o777, parents: bool = False, exist_ok: bool = False) -> None:
        try:
            self._sandbox.os.mkdir(self, mode)
        except FileNotFoundError:
            if not parents or self.parent == self:
                raise
            # The missing parents in one call rather than one per level.
            self._sandbox._fs(mkdir=api_pb2.FsMkdir(path=str(self.parent), is_recursive=True))
            self.mkdir(mode, parents=False, exist_ok=exist_ok)
        except OSError:
            if not exist_ok or not self.is_dir():
                raise

    def touch(self, mode: int = 0o666, exist_ok: bool = True) -> None:
        if exist_ok:
            try:
                self._sandbox.os.utime(self)
            except OSError:
                pass
            else:
                return
        flags = O_WRONLY | O_CREAT | (0 if exist_ok else O_EXCL)
        res = self._sandbox._fs(open=api_pb2.FsOpen(path=str(self), flags=flags, mode=mode))
        self._sandbox._fs(close=api_pb2.FsHandle(handle=res.handle))

    def unlink(self, missing_ok: bool = False) -> None:
        try:
            self._sandbox.os.unlink(self)
        except FileNotFoundError:
            if not missing_ok:
                raise

    def rmdir(self) -> None:
        self._sandbox.os.rmdir(self)

    def rename(self, target: Any) -> "SandboxPath":
        self._sandbox.os.rename(self, target)
        return type(self)(target)

    def replace(self, target: Any) -> "SandboxPath":
        self._sandbox.os.replace(self, target)
        return type(self)(target)

    def chmod(self, mode: int) -> None:
        self._sandbox.os.chmod(self, mode)

    def symlink_to(self, target: Any, target_is_directory: bool = False) -> None:
        self._sandbox.os.symlink(target, self, target_is_directory)

    def hardlink_to(self, target: Any) -> None:
        self._sandbox.os.link(target, self)

    def readlink(self) -> "SandboxPath":
        return type(self)(self._sandbox.os.readlink(self))

    def resolve(self, strict: bool = False) -> "SandboxPath":
        return type(self)(self._sandbox.os.path.realpath(self, strict=strict))
