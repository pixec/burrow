# A sandbox over fakes, with no server behind it. `Fs` calls are served by a
# real directory on this machine, so file semantics come from a real kernel;
# `Exec` and `Attach` run small scripted programs.

import errno
import os
import queue
import shutil
import threading

import pytest

from burrow import Sandbox
from burrow._pb import api_pb2, common_pb2
from burrow._transport import _DEFAULT
from burrow.sandbox import _to_sandbox_info

_ACCESS = {0: os.O_RDONLY, 1: os.O_WRONLY, 2: os.O_RDWR}
_LINUX_FLAGS = {0o100: os.O_CREAT, 0o200: os.O_EXCL, 0o1000: os.O_TRUNC, 0o2000: os.O_APPEND}
_CHUNK = 4 * 1024 * 1024


class LocalFs:
    """Answers `Fs` from a directory standing in for the guest's root."""

    def __init__(self, root):
        self.root = os.path.realpath(root)
        self.handles = {}
        self.calls = []

    def host(self, path):
        return os.path.join(self.root, path.lstrip("/"))

    def __call__(self, request):
        kind = request.WhichOneof("op")
        op = getattr(request, kind)
        self.calls.append((kind, op, request.user))
        try:
            return getattr(self, kind)(op)
        except OSError as err:
            path, dest = {
                "rename": ("src", "dst"),
                "copy": ("src", "dst"),
                "link": ("existing", "path"),
                "symlink": ("target", "path"),
            }.get(kind, ("path", ""))
            return api_pb2.FsResponse(
                error=api_pb2.FsError(
                    code=errno.errorcode[err.errno],
                    errno=err.errno,
                    syscall=kind,
                    path=getattr(op, path, ""),
                    dest=getattr(op, dest, "") if dest else "",
                )
            )

    def _stat(self, st):
        return api_pb2.FsResponse(
            stat=api_pb2.FsStatResult(
                dev=st.st_dev,
                ino=st.st_ino,
                mode=st.st_mode,
                nlink=st.st_nlink,
                uid=st.st_uid,
                gid=st.st_gid,
                rdev=st.st_rdev,
                size=st.st_size,
                blksize=st.st_blksize,
                blocks=st.st_blocks,
                atime_ns=st.st_atime_ns,
                mtime_ns=st.st_mtime_ns,
                ctime_ns=st.st_ctime_ns,
            )
        )

    def stat(self, op):
        return self._stat(os.stat(self.host(op.path), follow_symlinks=not op.is_nofollow))

    def read_dir(self, op):
        entries = []
        with os.scandir(self.host(op.path)) as it:
            for e in sorted(it, key=lambda e: e.name):
                kind = (
                    "symlink"
                    if e.is_symlink()
                    else "dir"
                    if e.is_dir(follow_symlinks=False)
                    else "file"
                )
                entries.append(api_pb2.FsDirEntry(name=e.name, type=kind))
        return api_pb2.FsResponse(entries=api_pb2.FsDirEntries(entries=entries))

    def mkdir(self, op):
        if op.is_recursive:
            os.makedirs(self.host(op.path), exist_ok=True)
            return api_pb2.FsResponse(path="")
        os.mkdir(self.host(op.path), op.mode or 0o777)
        return api_pb2.FsResponse(is_done=True)

    def remove(self, op):
        host = self.host(op.path)
        if op.is_recursive:
            shutil.rmtree(host)
        elif op.is_dir_only:
            os.rmdir(host)
        else:
            os.unlink(host)
        return api_pb2.FsResponse(is_done=True)

    def rename(self, op):
        os.rename(self.host(op.src), self.host(op.dst))
        return api_pb2.FsResponse(is_done=True)

    def copy(self, op):
        copy = shutil.copy2 if op.is_preserving else shutil.copyfile
        copy(self.host(op.src), self.host(op.dst))
        return api_pb2.FsResponse(is_done=True)

    def chmod(self, op):
        os.chmod(self.host(op.path), op.mode)
        return api_pb2.FsResponse(is_done=True)

    def utimes(self, op):
        os.utime(
            self.host(op.path),
            ns=(op.atime_ns, op.mtime_ns),
            follow_symlinks=not op.is_nofollow,
        )
        return api_pb2.FsResponse(is_done=True)

    def truncate(self, op):
        os.truncate(self.host(op.path), op.length)
        return api_pb2.FsResponse(is_done=True)

    def symlink(self, op):
        os.symlink(op.target, self.host(op.path))
        return api_pb2.FsResponse(is_done=True)

    def link(self, op):
        os.link(self.host(op.existing), self.host(op.path))
        return api_pb2.FsResponse(is_done=True)

    def readlink(self, op):
        return api_pb2.FsResponse(path=os.readlink(self.host(op.path)))

    def realpath(self, op):
        host = self.host(op.path)
        os.stat(host)
        resolved = os.path.realpath(host)
        return api_pb2.FsResponse(path="/" + os.path.relpath(resolved, self.root).lstrip("."))

    def access(self, op):
        if not os.access(self.host(op.path), op.mode):
            raise OSError(errno.EACCES, "denied")
        return api_pb2.FsResponse(is_done=True)

    def open(self, op):
        flags = _ACCESS[op.flags & 3]
        for linux, local in _LINUX_FLAGS.items():
            if op.flags & linux:
                flags |= local
        fd = os.open(self.host(op.path), flags, op.mode or 0o666)
        handle = len(self.handles) + 100
        self.handles[handle] = fd
        return api_pb2.FsResponse(handle=handle)

    def read(self, op):
        assert op.length <= _CHUNK
        fd = self.handles[op.handle]
        data = os.read(fd, op.length) if op.position < 0 else os.pread(fd, op.length, op.position)
        return api_pb2.FsResponse(data=data)

    def write(self, op):
        assert len(op.data) <= _CHUNK
        fd = self.handles[op.handle]
        n = os.write(fd, op.data) if op.position < 0 else os.pwrite(fd, op.data, op.position)
        return api_pb2.FsResponse(written=n)

    def fstat(self, op):
        return self._stat(os.fstat(self.handles[op.handle]))

    def ftruncate(self, op):
        os.ftruncate(self.handles[op.handle], op.length)
        return api_pb2.FsResponse(is_done=True)

    def close(self, op):
        os.close(self.handles.pop(op.handle))
        return api_pb2.FsResponse(is_done=True)


class FakeCall:
    """A streaming call whose responses come from a generator run on its own
    thread, as grpc's would arrive."""

    def __init__(self, responses):
        self._out = queue.Queue()
        self._cancelled = False
        threading.Thread(target=self._run, args=(responses,), daemon=True).start()

    def _run(self, responses):
        try:
            for msg in responses:
                if self._cancelled:
                    break
                self._out.put(msg)
        finally:
            self._out.put(None)

    def __iter__(self):
        return self

    def __next__(self):
        msg = self._out.get()
        if msg is None:
            self._out.put(None)
            raise StopIteration
        return msg

    def cancel(self):
        self._cancelled = True
        self._out.put(None)

    def cancelled(self):
        return self._cancelled


class Guest:
    """What a program sees: its argv, its stdin, and whether it was signalled."""

    def __init__(self, start, requests):
        self.start = start
        self.argv = list(start.cmd)
        self._requests = requests
        self.signalled = threading.Event()
        self.signal = 0

    def stdin(self):
        for msg in self._requests:
            kind = msg.WhichOneof("input")
            if kind == "stdin":
                yield msg.stdin
            elif kind == "is_stdin_eof":
                return


def out(data):
    return api_pb2.ExecOutput(stdout=data)


def err(data):
    return api_pb2.ExecOutput(stderr=data)


def exit_code(code):
    return api_pb2.ExecOutput(exit_code=code)


def echo(guest):
    """argv[1:] on stdout, as echo does."""
    yield out((" ".join(guest.argv[1:]) + "\n").encode())
    yield exit_code(0)


def cat(guest):
    for data in guest.stdin():
        yield out(data)
    yield exit_code(0)


def sleep(guest):
    guest.signalled.wait(10)
    yield api_pb2.ExecOutput(exit_signal=guest.signal)
    yield exit_code(128 + guest.signal)


class FakeTransport:
    host = "localhost"

    def __init__(self, root):
        self.fs = LocalFs(root)
        self.programs = {"echo": echo, "cat": cat, "sleep": sleep}
        self.started = []
        self.signals = []
        self.guests = {}
        self.attach = None

    def route(self, sandbox_id):
        return self

    def unary(self, method, request, timeout=_DEFAULT):
        if method == "Fs":
            return self.fs(request)
        if method == "SignalCommand":
            self.signals.append((request.command_id, request.signal))
            guest = self.guests[request.command_id]
            guest.signal = request.signal
            guest.signalled.set()
            return api_pb2.SignalCommandResponse()
        if method == "GetCommand":
            return api_pb2.CommandInfo(
                command_id=request.command_id, cmd=["/bin/sh"], state="running"
            )
        raise AssertionError(f"unexpected {method}")

    def duplex(self, method, requests, timeout):
        start = next(requests)
        if method == "Attach":
            return FakeCall(self.attach(start.start, Guest(api_pb2.ExecStart(), requests)))
        self.started.append(start.start)
        guest = Guest(start.start, requests)
        cmd_id = f"cmd_{len(self.started)}"
        self.guests[cmd_id] = guest
        program = self.programs[guest.argv[0]]

        def responses():
            yield api_pb2.ExecOutput(command_id=cmd_id)
            yield from program(guest)

        return FakeCall(responses())

    def retain(self):
        return self

    def close(self):
        pass


@pytest.fixture
def transport(tmp_path):
    return FakeTransport(tmp_path)


@pytest.fixture
def sandbox(transport):
    return Sandbox(transport, _to_sandbox_info(common_pb2.Sandbox(id="sbx_test")), False)


@pytest.fixture
def root(transport):
    """The host directory the sandbox's `/` is."""
    return transport.fs.root
