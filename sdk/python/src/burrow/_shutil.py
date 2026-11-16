"""The sandbox's `shutil` methods: the stdlib's high-level file operations.

The algorithms are CPython's, built on the sandbox's `os` methods, with two
exceptions where the guest can do in one call what they do in many: a file's
bytes are copied by the guest rather than read out and written back, and
`rmtree` asks the guest to remove the whole tree before walking it.
"""

from __future__ import annotations

import posixpath
import shutil
import stat
from typing import Any, Callable, List, Optional

from ._os import OsMixin, fspath
from ._pb import api_pb2


class ShutilMixin(OsMixin):
    """`shutil`, as `Sandbox` methods. Errors are the stdlib's own classes, so
    `except shutil.Error` catches them. `shutil.move` is `move_path`, since
    `Sandbox.move` moves the sandbox to another node."""

    def _samefile(self, src: Any, dst: Any) -> bool:
        try:
            return self.samefile(src, dst)
        except OSError:
            return False

    def _copyfile(self, src: Any, dst: Any, follow_symlinks: bool, preserve: bool) -> None:
        if self._samefile(src, dst):
            raise shutil.SameFileError(f"{src!r} and {dst!r} are the same file")
        if not follow_symlinks and self.islink(src):
            self.symlink(self.readlink(src), dst)
            if preserve:
                self.copystat(src, dst, follow_symlinks=False)
            return
        self._fs(
            copy=api_pb2.FsCopy(src=fspath(src), dst=fspath(dst), is_preserving=preserve)
        )

    def copyfile(self, src: Any, dst: Any, *, follow_symlinks: bool = True) -> Any:
        self._copyfile(src, dst, follow_symlinks, preserve=False)
        return dst

    def copymode(self, src: Any, dst: Any, *, follow_symlinks: bool = True) -> None:
        if not follow_symlinks and self.islink(src) and self.islink(dst):
            # Linux has no lchmod, and there the stdlib leaves a link's mode
            # alone too.
            return
        self.chmod(dst, stat.S_IMODE(self.stat(src).st_mode))

    def copystat(self, src: Any, dst: Any, *, follow_symlinks: bool = True) -> None:
        follow = follow_symlinks or not (self.islink(src) and self.islink(dst))
        st = self.stat(src, follow_symlinks=follow)
        self.utime(dst, ns=(st.st_atime_ns, st.st_mtime_ns), follow_symlinks=follow)
        if follow:
            self.chmod(dst, stat.S_IMODE(st.st_mode))

    def copy(self, src: Any, dst: Any, *, follow_symlinks: bool = True) -> Any:
        if self.isdir(dst):
            dst = posixpath.join(dst, posixpath.basename(src))
        self.copyfile(src, dst, follow_symlinks=follow_symlinks)
        self.copymode(src, dst, follow_symlinks=follow_symlinks)
        return dst

    def copy2(self, src: Any, dst: Any, *, follow_symlinks: bool = True) -> Any:
        if self.isdir(dst):
            dst = posixpath.join(dst, posixpath.basename(src))
        # The guest carries mode and times over in the same call as the bytes.
        self._copyfile(src, dst, follow_symlinks, preserve=True)
        return dst

    def copytree(
        self,
        src: Any,
        dst: Any,
        symlinks: bool = False,
        ignore: Optional[Callable[[str, List[str]], Any]] = None,
        copy_function: Optional[Callable[[Any, Any], Any]] = None,
        ignore_dangling_symlinks: bool = False,
        dirs_exist_ok: bool = False,
    ) -> Any:
        """`shutil.copytree`. `copy_function` defaults to this sandbox's
        `copy2`, as the stdlib's defaults to its own."""
        copy_function = copy_function or self.copy2
        with self.scandir(src) as itr:
            entries = list(itr)
        if ignore is not None:
            ignored_names = ignore(fspath(src), [x.name for x in entries])
        else:
            ignored_names = ()

        self.makedirs(dst, exist_ok=dirs_exist_ok)
        errors: List[Any] = []
        for srcentry in entries:
            if srcentry.name in ignored_names:
                continue
            srcname = posixpath.join(src, srcentry.name)
            dstname = posixpath.join(dst, srcentry.name)
            try:
                if srcentry.is_symlink():
                    linkto = self.readlink(srcname)
                    if symlinks:
                        self.symlink(linkto, dstname)
                        self.copystat(srcname, dstname, follow_symlinks=not symlinks)
                    else:
                        if not self.exists(linkto) and ignore_dangling_symlinks:
                            continue
                        if srcentry.is_dir():
                            self.copytree(
                                srcname,
                                dstname,
                                symlinks,
                                ignore,
                                copy_function,
                                ignore_dangling_symlinks,
                                dirs_exist_ok,
                            )
                        else:
                            copy_function(srcname, dstname)
                elif srcentry.is_dir():
                    self.copytree(
                        srcname,
                        dstname,
                        symlinks,
                        ignore,
                        copy_function,
                        ignore_dangling_symlinks,
                        dirs_exist_ok,
                    )
                else:
                    copy_function(srcname, dstname)
            # A subtree's errors are collected rather than ending the copy.
            except shutil.Error as err:
                errors.extend(err.args[0])
            except OSError as why:
                errors.append((srcname, dstname, str(why)))
        try:
            self.copystat(src, dst)
        except OSError as why:
            errors.append((src, dst, str(why)))
        if errors:
            raise shutil.Error(errors)
        return dst

    def rmtree(
        self,
        path: Any,
        ignore_errors: bool = False,
        onerror: Optional[Callable[..., Any]] = None,
        *,
        onexc: Optional[Callable[..., Any]] = None,
    ) -> None:
        """`shutil.rmtree`.

        The guest removes the tree in one call. Only when that fails, and the
        caller asked to hear about failures or to ignore them, is the rest
        walked here, so that each failure reaches the handler and removal
        carries on past it as the stdlib's does.
        """
        tolerant = ignore_errors or onerror is not None or onexc is not None
        if ignore_errors:

            def onexc(*args: Any) -> None:
                pass

        elif onerror is None and onexc is None:

            def onexc(*args: Any) -> None:
                raise

        elif onexc is None:

            def onexc(*args: Any) -> Any:
                func, path, exc = args
                exc_info = (None, None, None) if exc is None else (type(exc), exc, exc.__traceback__)
                return onerror(func, path, exc_info)

        try:
            st = self.lstat(path)
        except OSError as err:
            onexc(self.lstat, path, err)
            return
        try:
            if stat.S_ISLNK(st.st_mode):
                raise OSError("Cannot call rmtree on a symbolic link")
        except OSError as err:
            onexc(self.islink, path, err)
            return
        try:
            self._fs(remove=api_pb2.FsRemove(path=fspath(path), is_recursive=True))
            return
        except OSError:
            if not tolerant:
                raise
        self._rmtree_walk(fspath(path), onexc)

    def _rmtree_walk(self, path: str, onexc: Callable[..., Any]) -> None:
        try:
            with self.scandir(path) as itr:
                entries = list(itr)
        except FileNotFoundError:
            return
        except OSError as err:
            onexc(self.scandir, path, err)
            entries = []
        for entry in entries:
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                is_dir = False
            if is_dir:
                self._rmtree_walk(entry.path, onexc)
                continue
            try:
                self.remove(entry.path)
            except FileNotFoundError:
                continue
            except OSError as err:
                onexc(self.remove, entry.path, err)
        try:
            self.rmdir(path)
        except FileNotFoundError:
            pass
        except OSError as err:
            onexc(self.rmdir, path, err)

    def move_path(self, src: Any, dst: Any, copy_function: Optional[Callable[[Any, Any], Any]] = None) -> Any:
        """`shutil.move`. `copy_function` defaults to this sandbox's `copy2`."""
        copy_function = copy_function or self.copy2
        real_dst = dst
        if self.isdir(dst):
            if self._samefile(src, dst) and not self.islink(src):
                self.rename(src, dst)
                return None
            # A trailing slash is stripped first, or the basename is empty.
            real_dst = posixpath.join(dst, posixpath.basename(fspath(src).rstrip("/")))
            if self.exists(real_dst):
                raise shutil.Error(f"Destination path '{real_dst}' already exists")
        try:
            self.rename(src, real_dst)
        except OSError:
            if self.islink(src):
                self.symlink(self.readlink(src), real_dst)
                self.remove(src)
            elif self.isdir(src):
                if _destinsrc(src, dst):
                    raise shutil.Error(
                        f"Cannot move a directory '{src}' into itself '{dst}'."
                    )
                self.copytree(src, real_dst, copy_function=copy_function, symlinks=True)
                self.rmtree(src)
            else:
                copy_function(src, real_dst)
                self.remove(src)
        return real_dst


def _destinsrc(src: Any, dst: Any) -> bool:
    src = posixpath.normpath(fspath(src)) + "/"
    dst = posixpath.normpath(fspath(dst)) + "/"
    return dst.startswith(src)
