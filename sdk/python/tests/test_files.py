# `sandbox.open`, `sandbox.os`, `sandbox.shutil` and `sandbox.Path` against
# the fake guest in conftest.py, whose filesystem is a real directory.

import errno
import io
import os
import shutil
import stat

import pytest

from burrow import BurrowError
from burrow._os import os_error
from burrow._pb import api_pb2

MiB = 1024 * 1024


def calls(transport, kind):
    return [op for k, op, _ in transport.fs.calls if k == kind]


# Errors


def test_an_errno_picks_the_stdlib_subclass_by_name():
    error = os_error(api_pb2.FsError(code="ENOENT", errno=2, syscall="stat", path="/x"))
    assert type(error) is FileNotFoundError
    assert (error.errno, error.strerror, error.filename) == (
        errno.ENOENT,
        os.strerror(errno.ENOENT),
        "/x",
    )
    assert error.filename2 is None


def test_a_second_path_is_filename2():
    error = os_error(
        api_pb2.FsError(code="EEXIST", errno=17, syscall="link", path="/a", dest="/b")
    )
    assert type(error) is FileExistsError
    assert (error.filename, error.filename2) == ("/a", "/b")


def test_a_linux_errno_is_renumbered_for_this_platform():
    # ENOTEMPTY is 39 on Linux; this machine may call it something else.
    error = os_error(api_pb2.FsError(code="ENOTEMPTY", errno=39, path="/d"))
    assert error.errno == errno.ENOTEMPTY
    assert error.strerror == os.strerror(errno.ENOTEMPTY)


def test_scope_and_size_refusals_are_plain_oserrors():
    assert type(os_error(api_pb2.FsError(code="EACCES", errno=13))) is PermissionError
    big = os_error(api_pb2.FsError(code="EFBIG", errno=27, path="/big"))
    assert type(big) is OSError and big.errno == errno.EFBIG


def test_kernel_errors_raise_from_calls(sandbox):
    with pytest.raises(FileNotFoundError) as caught:
        sandbox.os.stat("/missing")
    assert caught.value.filename == "/missing"
    with pytest.raises(FileNotFoundError) as caught:
        sandbox.os.rename("/missing", "/elsewhere")
    assert (caught.value.filename, caught.value.filename2) == ("/missing", "/elsewhere")


def test_a_policy_refusal_stays_a_burrow_error(sandbox, transport):
    def refuse(request):
        raise BurrowError("path is outside the sandbox's scopes", "permission_denied")

    transport.fs = refuse
    with pytest.raises(BurrowError):
        sandbox.os.listdir("/")


def test_a_user_handle_names_its_user_on_every_call(sandbox, transport):
    sandbox.as_user("alice").os.path.exists("/")
    assert transport.fs.calls[-1][2] == "alice"


# open()


def test_text_round_trip(sandbox, root):
    with sandbox.open("/a.txt", "w") as f:
        assert f.write("héllo\n") == 6
        assert f.mode == "w" and f.name == "/a.txt"
    with open(os.path.join(root, "a.txt"), "rb") as f:
        assert f.read() == "héllo\n".encode()
    with sandbox.open("/a.txt") as f:
        assert isinstance(f, io.TextIOWrapper)
        assert f.read() == "héllo\n"


def test_binary_modes_return_buffered_objects(sandbox):
    with sandbox.open("/b", "wb") as f:
        assert isinstance(f, io.BufferedWriter)
        f.write(bytes(range(256)))
    with sandbox.open("/b", "rb") as f:
        assert isinstance(f, io.BufferedReader)
        assert f.read() == bytes(range(256))
    with sandbox.open("/b", "rb", buffering=0) as f:
        assert f.read(3) == b"\x00\x01\x02"


def test_modes_send_linux_open_flags(sandbox, transport):
    for mode in ("w", "a", "x", "r", "r+", "w+", "a+"):
        if mode == "x":
            sandbox.os.remove("/f")
        sandbox.open("/f", mode).close()
    flags = [op.flags for op in calls(transport, "open")]
    assert flags == [
        0o1 | 0o100 | 0o1000,
        0o1 | 0o100 | 0o2000,
        0o1 | 0o100 | 0o200,
        0,
        0o2,
        0o2 | 0o100 | 0o1000,
        0o2 | 0o100 | 0o2000,
    ]


def test_x_refuses_an_existing_file(sandbox):
    sandbox.open("/f", "w").close()
    with pytest.raises(FileExistsError) as caught:
        sandbox.open("/f", "x")
    assert caught.value.filename == "/f"


def test_reading_a_missing_file(sandbox):
    with pytest.raises(FileNotFoundError):
        sandbox.open("/nope")


def test_a_appends_wherever_the_position_is(sandbox):
    with sandbox.open("/log", "w") as f:
        f.write("one\n")
    with sandbox.open("/log", "a+") as f:
        assert f.tell() == 4
        f.write("two\n")
        f.seek(0)
        assert f.read() == "one\ntwo\n"
        f.seek(0)
        f.write("three\n")
        assert f.tell() == 14
    assert sandbox.open("/log").read() == "one\ntwo\nthree\n"


def test_plus_reads_and_writes_one_file(sandbox):
    with sandbox.open("/rw", "w+") as f:
        f.write("abcdef")
        f.seek(2)
        assert f.read(2) == "cd"
        f.seek(0)
        f.write("X")
    with sandbox.open("/rw", "r+b") as f:
        assert f.read() == b"Xbcdef"
        f.truncate(3)
    assert sandbox.os.stat("/rw").st_size == 3


def test_a_misused_mode_fails_as_the_stdlib_does(sandbox):
    with pytest.raises(ValueError, match="invalid mode"):
        sandbox.open("/f", "rr")
    with pytest.raises(ValueError, match="exactly one of"):
        sandbox.open("/f", "rw")
    with pytest.raises(ValueError, match="binary mode doesn't take an encoding"):
        sandbox.open("/f", "wb", encoding="utf-8")
    with pytest.raises(ValueError, match="unbuffered text"):
        sandbox.open("/f", "w", buffering=0)
    with sandbox.open("/f", "w") as f:
        with pytest.raises(io.UnsupportedOperation):
            f.read()
    with pytest.raises(ValueError):
        f.write("closed")


def test_fileno_has_no_local_descriptor(sandbox):
    with sandbox.open("/f", "w") as f:
        with pytest.raises(io.UnsupportedOperation):
            f.fileno()


def test_large_io_goes_in_4_mib_calls_at_explicit_positions(sandbox, transport):
    blob = os.urandom(9 * MiB + 5)
    with sandbox.open("/big", "wb") as f:
        assert f.write(blob) == len(blob)
    writes = calls(transport, "write")
    assert [len(op.data) for op in writes] == [4 * MiB, 4 * MiB, MiB + 5]
    assert [op.position for op in writes] == [0, 4 * MiB, 8 * MiB]

    with sandbox.open("/big", "rb") as f:
        assert f.read() == blob
        f.seek(5 * MiB)
        assert f.tell() == 5 * MiB
        assert f.read(10) == blob[5 * MiB : 5 * MiB + 10]
        f.seek(-3, os.SEEK_END)
        assert f.read() == blob[-3:]
        f.seek(0)
        assert f.read(6 * MiB) == blob[: 6 * MiB]
        assert f.tell() == 6 * MiB
    assert all(op.length <= 4 * MiB for op in calls(transport, "read"))
    assert all(op.position >= 0 for op in calls(transport, "read"))


def test_readline_iteration_and_newlines(sandbox):
    with sandbox.open("/lines", "wb") as f:
        f.write(b"a\nb\r\nc\rd")
    with sandbox.open("/lines") as f:
        assert f.readline() == "a\n"
        assert list(f) == ["b\n", "c\n", "d"]
    with sandbox.open("/lines", newline="") as f:
        assert f.readlines() == ["a\n", "b\r\n", "c\r", "d"]
    with sandbox.open("/lines", "rb") as f:
        assert list(f) == [b"a\n", b"b\r\n", b"c\rd"]


def test_a_text_file_seeks_to_where_it_told(sandbox):
    sandbox.Path("/t").write_text("first\nsecond\n")
    with sandbox.open("/t") as f:
        f.readline()
        mark = f.tell()
        f.read()
        f.seek(mark)
        assert f.read() == "second\n"


# os


def test_stat_is_a_real_stat_result(sandbox, root):
    with open(os.path.join(root, "s"), "wb") as f:
        f.write(b"12345")
    local = os.stat(os.path.join(root, "s"))
    st = sandbox.os.stat("/s")
    assert isinstance(st, os.stat_result)
    assert stat.S_ISREG(st.st_mode)
    assert st.st_size == 5 and st[6] == 5
    assert st.st_ino == local.st_ino
    assert st.st_mtime_ns == local.st_mtime_ns
    assert isinstance(st.st_mtime, float) and abs(st.st_mtime - local.st_mtime) < 1e-6
    assert st[8] == int(local.st_mtime)
    assert st.st_blksize == local.st_blksize


def test_utime_and_lstat(sandbox):
    sandbox.open("/u", "w").close()
    sandbox.os.utime("/u", ns=(1_000_000_000_123, 2_000_000_000_456))
    st = sandbox.os.stat("/u")
    assert (st.st_atime_ns, st.st_mtime_ns) == (1_000_000_000_123, 2_000_000_000_456)
    sandbox.os.utime("/u", (10, 20.5))
    assert sandbox.os.stat("/u").st_mtime == 20.5
    with pytest.raises(ValueError):
        sandbox.os.utime("/u", (1, 2), ns=(1, 2))
    sandbox.os.symlink("u", "/link")
    assert stat.S_ISLNK(sandbox.os.lstat("/link").st_mode)
    assert sandbox.os.readlink("/link") == "u"


def test_scandir_and_listdir(sandbox):
    sandbox.os.mkdir("/d")
    sandbox.os.mkdir("/d/sub")
    sandbox.Path("/d/file").write_bytes(b"xyz")
    sandbox.os.symlink("sub", "/d/link")
    sandbox.os.symlink("missing", "/d/dangling")
    assert sorted(sandbox.os.listdir("/d")) == ["dangling", "file", "link", "sub"]
    with sandbox.os.scandir("/d") as it:
        entries = {e.name: e for e in it}
    assert entries["sub"].path == "/d/sub"
    assert entries["sub"].is_dir() and not entries["sub"].is_file()
    assert entries["file"].is_file() and entries["file"].stat().st_size == 3
    assert entries["link"].is_symlink() and entries["link"].is_dir()
    assert not entries["link"].is_dir(follow_symlinks=False)
    assert not entries["dangling"].is_dir() and not entries["dangling"].is_file()
    assert entries["file"].inode() == sandbox.os.stat("/d/file").st_ino
    assert os.fspath(entries["file"]) == "/d/file"


def test_walk(sandbox):
    sandbox.os.makedirs("/w/a/b")
    sandbox.Path("/w/a/f").touch()
    sandbox.os.symlink("a", "/w/link")
    top = list(sandbox.os.walk("/w"))
    assert top[0] == ("/w", ["a", "link"], [])
    assert ("/w/a", ["b"], ["f"]) in top
    assert all(not path.startswith("/w/link") for path, _, _ in top)
    bottom = [path for path, _, _ in sandbox.os.walk("/w", topdown=False)]
    assert bottom == ["/w/a/b", "/w/a", "/w"]


def test_makedirs_exist_ok(sandbox):
    sandbox.os.makedirs("/m/a/b", mode=0o700)
    assert sandbox.os.path.isdir("/m/a/b")
    with pytest.raises(FileExistsError):
        sandbox.os.makedirs("/m/a/b")
    sandbox.os.makedirs("/m/a/b", exist_ok=True)
    sandbox.open("/m/file", "w").close()
    with pytest.raises(FileExistsError):
        sandbox.os.makedirs("/m/file", exist_ok=True)


def test_remove_rmdir_removedirs(sandbox):
    sandbox.os.makedirs("/r/a/b")
    with pytest.raises(OSError) as caught:
        sandbox.os.rmdir("/r/a")
    assert caught.value.errno == errno.ENOTEMPTY
    sandbox.os.removedirs("/r/a/b")
    assert not sandbox.os.path.exists("/r")
    with pytest.raises(FileNotFoundError):
        sandbox.os.remove("/r")


def test_os_path(sandbox):
    sandbox.os.mkdir("/p")
    sandbox.Path("/p/f.txt").write_text("hello")
    sandbox.os.symlink("f.txt", "/p/l")
    sandbox.os.symlink("nothing", "/p/broken")
    path = sandbox.os.path
    assert path.exists("/p/f.txt") and not path.exists("/p/broken")
    assert path.lexists("/p/broken")
    assert path.isfile("/p/l") and path.islink("/p/l") and path.isdir("/p")
    assert path.getsize("/p/f.txt") == 5
    assert path.getmtime("/p/f.txt") == sandbox.os.stat("/p/f.txt").st_mtime
    assert path.realpath("/p/l") == "/p/f.txt"
    assert path.realpath("/p/missing/../x") == "/p/x"
    with pytest.raises(FileNotFoundError):
        path.realpath("/p/missing", strict=True)
    assert path.samefile("/p/l", "/p/f.txt")
    assert path.join("/p", "f.txt") == "/p/f.txt"
    assert path.splitext("/p/f.txt") == ("/p/f", ".txt")


def test_access(sandbox):
    sandbox.open("/x", "w").close()
    assert sandbox.os.access("/x", sandbox.os.R_OK | sandbox.os.W_OK)
    assert not sandbox.os.access("/x", sandbox.os.X_OK)
    assert not sandbox.os.access("/missing", sandbox.os.F_OK)


# shutil


def tree(sandbox):
    sandbox.os.makedirs("/src/sub")
    sandbox.Path("/src/a.txt").write_text("a")
    sandbox.Path("/src/sub/b.txt").write_text("b")
    sandbox.os.symlink("a.txt", "/src/link")
    sandbox.os.chmod("/src/a.txt", 0o640)


def test_copytree_follows_or_keeps_symlinks(sandbox):
    tree(sandbox)
    assert sandbox.shutil.copytree("/src", "/dst") == "/dst"
    assert sandbox.Path("/dst/sub/b.txt").read_text() == "b"
    assert not sandbox.os.path.islink("/dst/link")
    assert sandbox.Path("/dst/link").read_text() == "a"
    assert stat.S_IMODE(sandbox.os.stat("/dst/a.txt").st_mode) == 0o640

    sandbox.shutil.copytree("/src", "/kept", symlinks=True)
    assert sandbox.os.readlink("/kept/link") == "a.txt"

    with pytest.raises(FileExistsError):
        sandbox.shutil.copytree("/src", "/dst")
    sandbox.Path("/src/new.txt").write_text("new")
    sandbox.shutil.copytree("/src", "/dst", dirs_exist_ok=True)
    assert sandbox.Path("/dst/new.txt").read_text() == "new"

    sandbox.shutil.copytree("/src", "/some", ignore=sandbox.shutil.ignore_patterns("*.txt"))
    assert sorted(sandbox.os.listdir("/some")) == ["link", "sub"]


def test_rmtree(sandbox, transport):
    tree(sandbox)
    sandbox.shutil.rmtree("/src")
    assert not sandbox.os.path.exists("/src")
    assert len(calls(transport, "remove")) == 1
    with pytest.raises(FileNotFoundError):
        sandbox.shutil.rmtree("/src")
    sandbox.shutil.rmtree("/src", ignore_errors=True)

    tree(sandbox)
    with pytest.raises(OSError, match="symbolic link"):
        sandbox.shutil.rmtree("/src/link")
    seen = []
    sandbox.shutil.rmtree("/src/link", onexc=lambda func, path, exc: seen.append(path))
    assert seen == ["/src/link"]


def test_copy_copy2_and_move(sandbox):
    tree(sandbox)
    sandbox.os.utime("/src/a.txt", ns=(5_000_000_000, 6_000_000_000))
    assert sandbox.shutil.copy("/src/a.txt", "/src/sub") == "/src/sub/a.txt"
    assert stat.S_IMODE(sandbox.os.stat("/src/sub/a.txt").st_mode) == 0o640
    sandbox.shutil.copy2("/src/a.txt", "/c2")
    assert sandbox.os.stat("/c2").st_mtime_ns == 6_000_000_000
    with pytest.raises(shutil.SameFileError):
        sandbox.shutil.copyfile("/src/a.txt", "/src/link")
    assert sandbox.shutil.move("/c2", "/src/sub") == "/src/sub/c2"
    with pytest.raises(shutil.Error, match="already exists"):
        sandbox.shutil.move("/src/sub/c2", "/src/sub")


# Path


def test_pure_operations_stay_bound(sandbox):
    work = sandbox.Path("/work")
    app = work / "app.py"
    assert isinstance(app, sandbox.Path) and isinstance(app.parent, sandbox.Path)
    assert isinstance(app.with_suffix(".txt"), sandbox.Path)
    assert str(app) == "/work/app.py" and app.name == "app.py"
    assert not isinstance(app, sandbox.as_user("bob").Path)


def test_path_ops(sandbox):
    work = sandbox.Path("/work/deep")
    with pytest.raises(FileNotFoundError):
        work.mkdir()
    work.mkdir(parents=True)
    work.mkdir(exist_ok=True)
    app = work / "app.py"
    assert app.write_text("print(1)\n") == 9
    assert app.read_text() == "print(1)\n" and app.read_bytes() == b"print(1)\n"
    assert app.exists() and app.is_file() and not app.is_dir()
    assert sorted(p.name for p in work.iterdir()) == ["app.py"]
    assert all(isinstance(p, sandbox.Path) for p in work.iterdir())
    with pytest.raises(TypeError):
        app.write_text(b"bytes")

    moved = app.rename(work / "main.py")
    assert isinstance(moved, sandbox.Path) and moved.exists() and not app.exists()

    link = work / "link"
    link.symlink_to("main.py")
    assert link.is_symlink() and link.readlink() == sandbox.Path("main.py")
    assert link.resolve() == moved and link.samefile(moved)
    assert link.samefile("/work/deep/main.py")

    (work / "t").touch()
    with pytest.raises(FileExistsError):
        (work / "t").touch(exist_ok=False)
    (work / "t").chmod(0o600)
    assert stat.S_IMODE((work / "t").stat().st_mode) == 0o600
    (work / "t").unlink()
    (work / "t").unlink(missing_ok=True)
    with pytest.raises(FileNotFoundError):
        (work / "t").unlink()
    with sandbox.Path("/work/deep/main.py").open() as f:
        assert f.readline() == "print(1)\n"
