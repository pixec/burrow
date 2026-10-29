"""`sandbox.subprocess`: the `subprocess` module, for commands in the sandbox.

`Popen` drives one `Exec` stream (or, from `Sandbox.get_command`, one
`Attach`). A thread reads the stream for as long as it lasts and hands each
piece of output to wherever that stream was sent: a pipe the caller reads, a
local descriptor, or nowhere. The rest is the stdlib's own definitions over
that, with its exception classes and constants rather than copies of them.
"""

from __future__ import annotations

import errno
import io
import itertools
import os
import queue
import signal
import subprocess
import threading
from subprocess import (
    DEVNULL,
    PIPE,
    STDOUT,
    CalledProcessError,
    CompletedProcess,
    SubprocessError,
    TimeoutExpired,
)
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional, Tuple

import grpc

from ._pb import api_pb2
from .errors import BurrowError

if TYPE_CHECKING:
    from .sandbox import Sandbox
    from .types import CommandInfo

# Bytes per stdin message, matching HTTP/2's default flow-control window.
_STDIN_CHUNK = 64 * 1024

# Signal numbers on the guest, which is Linux. Several differ elsewhere
# (SIGUSR1 is 30 on macOS), so a signal crosses by name: the guest is sent its
# own number for what the caller named, and a signal exit reports this
# platform's number for what the guest named.
_LINUX_SIGNALS = {
    "SIGHUP": 1,
    "SIGINT": 2,
    "SIGQUIT": 3,
    "SIGILL": 4,
    "SIGTRAP": 5,
    "SIGABRT": 6,
    "SIGBUS": 7,
    "SIGFPE": 8,
    "SIGKILL": 9,
    "SIGUSR1": 10,
    "SIGSEGV": 11,
    "SIGUSR2": 12,
    "SIGPIPE": 13,
    "SIGALRM": 14,
    "SIGTERM": 15,
    "SIGCHLD": 17,
    "SIGCONT": 18,
    "SIGSTOP": 19,
    "SIGTSTP": 20,
    "SIGTTIN": 21,
    "SIGTTOU": 22,
    "SIGURG": 23,
    "SIGXCPU": 24,
    "SIGXFSZ": 25,
    "SIGVTALRM": 26,
    "SIGPROF": 27,
    "SIGWINCH": 28,
    "SIGIO": 29,
    "SIGSYS": 31,
}


def _to_linux_signal(sig: int) -> int:
    try:
        return _LINUX_SIGNALS.get(signal.Signals(sig).name, int(sig))
    except ValueError:
        return int(sig)


def _from_linux_signal(number: int) -> int:
    for name, linux in _LINUX_SIGNALS.items():
        if linux == number:
            return int(getattr(signal, name, number))
    return number


def _argv(args: Any, shell: bool) -> List[str]:
    """The command as the stdlib builds it on POSIX: a lone string is the
    program, unless `shell` hands it to `/bin/sh -c`."""
    if isinstance(args, (str, bytes)):
        argv = [args]
    elif isinstance(args, os.PathLike):
        if shell:
            raise TypeError("path-like args is not allowed when shell is true")
        argv = [args]
    else:
        argv = list(args)
    if shell:
        argv = ["/bin/sh", "-c", *argv]
    return [os.fsdecode(arg) for arg in argv]


def _drain(inputs: "queue.Queue[Any]") -> Iterator[Any]:
    while True:
        item = inputs.get()
        if item is None:
            return
        yield item


def _buffered(raw: Any, kind: Any, bufsize: int) -> Any:
    if bufsize == 0:
        return raw
    return kind(raw, io.DEFAULT_BUFFER_SIZE if bufsize < 0 or bufsize == 1 else bufsize)


class _OutputPipe(io.RawIOBase):
    """The read end of a command's stdout or stderr.

    Filled by the thread reading the stream, so a command writing to both
    never stalls on the one nobody is reading. The price is that output
    nobody reads is held here, where an OS pipe would block the writer.
    """

    def __init__(self) -> None:
        super().__init__()
        self._data = bytearray()
        self._ended = False
        self._ready = threading.Condition()

    def readable(self) -> bool:
        return True

    def feed(self, data: bytes) -> None:
        with self._ready:
            if not self.closed:
                self._data += data
                self._ready.notify_all()

    def finish(self) -> None:
        with self._ready:
            self._ended = True
            self._ready.notify_all()

    def readinto(self, buffer: Any) -> int:
        with self._ready:
            while not self._data and not self._ended:
                self._ready.wait()
            n = min(len(buffer), len(self._data))
            with memoryview(buffer) as view, view.cast("B") as target:
                target[:n] = self._data[:n]
            del self._data[:n]
            return n


class _InputPipe(io.RawIOBase):
    """The write end of a command's stdin. Closing it is EOF to the command."""

    def __init__(self, popen: "Popen"):
        super().__init__()
        self._popen = popen

    def writable(self) -> bool:
        return True

    def write(self, b: Any) -> int:
        if self._popen._done.is_set():
            raise BrokenPipeError(errno.EPIPE, os.strerror(errno.EPIPE))
        with memoryview(b) as view, view.cast("B") as source:
            data = source[:_STDIN_CHUNK].tobytes()
        self._popen._send(stdin=data)
        return len(data)

    def close(self) -> None:
        if not self.closed and not self._popen._done.is_set() and not self._popen._detached:
            self._popen._send(is_stdin_eof=True)
        super().close()


def _write_fd(fd: int, data: bytes) -> None:
    while data:
        data = data[os.write(fd, data) :]


class Popen:
    """`subprocess.Popen`, for a command in the sandbox.

    The stdlib's arguments mean what they mean there, with these differences,
    each because the command is not this process's child:

    - `stdin=None` is EOF, where the stdlib would hand over this process's
      own stdin. `stdout=None` and `stderr=None` do inherit: output goes to
      this process's descriptors 1 and 2, as a child's would. A descriptor or
      a file with `fileno()` works for all three.
    - `env` is laid over the guest's environment, and the handle's, rather
      than replacing it.
    - Text mode decodes UTF-8 unless `encoding` says otherwise, where the
      stdlib would take this machine's locale encoding.
    - `pid` is None; the guest does not expose it. `cmd_id` names the
      command to `Sandbox.get_command` and `list_commands` instead.
    - `user` names a guest user, as the stdlib's names a local one.

    Burrow's own, with no stdlib counterpart: `pty` runs the command on a
    terminal (stderr then arrives on stdout), and `log_max_bytes` and
    `log_max_files` rotate the output the node keeps for later attaches, as
    Docker's `max-size` and `max-file` do; unset keeps every byte.
    """

    _sandbox: "Sandbox"

    def __init__(
        self,
        args: Any,
        bufsize: int = -1,
        stdin: Any = None,
        stdout: Any = None,
        stderr: Any = None,
        shell: bool = False,
        cwd: Any = None,
        env: Optional[Dict[str, str]] = None,
        universal_newlines: Optional[bool] = None,
        *,
        encoding: Optional[str] = None,
        errors: Optional[str] = None,
        text: Optional[bool] = None,
        user: Optional[str] = None,
        pty: bool = False,
        log_max_bytes: int = 0,
        log_max_files: int = 0,
    ):
        sandbox = self._sandbox
        sandbox._assert_live()
        if universal_newlines is not None and text is not None and bool(universal_newlines) != bool(text):
            raise SubprocessError(
                "Cannot disambiguate when both text and universal_newlines are "
                "supplied but different. Pass one or the other."
            )
        self._setup(
            args, bool(encoding or errors or text or universal_newlines), api_pb2.ExecInput
        )
        self._readers(stdout, stderr, bufsize, encoding, errors)
        start = api_pb2.ExecInput(
            start=api_pb2.ExecStart(
                sandbox_id=sandbox.id,
                cmd=_argv(args, shell),
                # A per-command variable wins over the handle's defaults.
                env={**sandbox._env, **(env or {})},
                cwd=os.fsdecode(cwd) if cwd is not None else "",
                is_pty=pty,
                rows=24,
                cols=80,
                user=sandbox._default_user if user is None else user,
                log_max_bytes=log_max_bytes,
                log_max_files=log_max_files,
            )
        )

        def begin() -> Tuple["queue.Queue[Any]", Any, Any]:
            inputs: "queue.Queue[Any]" = queue.Queue()
            inputs.put(start)
            # A command outlives any request deadline; `timeout` is what
            # bounds the wait for one.
            call = sandbox._transport.route(sandbox.id).duplex("Exec", _drain(inputs), None)
            # The guest names the command before anything else, and refuses
            # one (exec denied, sandbox suspended) here.
            try:
                first = next(call, None)
            except grpc.RpcError as err:
                inputs.put(None)
                raise BurrowError.from_grpc(err) from None
            return inputs, call, first

        self._inputs, call, first = sandbox._with_resume(begin)
        if first is not None and first.WhichOneof("output") == "command_id":
            self.cmd_id = first.command_id
            first = None
        self._pump_in_background(call, first)

        if stdin == PIPE:
            self._pipe_stdin(bufsize, encoding, errors)
        elif stdin is None or stdin == DEVNULL:
            self._send(is_stdin_eof=True)
        else:
            fd = stdin if isinstance(stdin, int) else stdin.fileno()
            threading.Thread(target=self._feed, args=(fd,), daemon=True).start()

    @classmethod
    def _attach(
        cls,
        info: "CommandInfo",
        from_offset: int,
        encoding: Optional[str],
        errors: Optional[str],
        text: Optional[bool],
    ) -> "Popen":
        """A handle on a command already running, or finished, over `Attach`:
        its output replayed from `from_offset` and then followed, and its
        stdin fed. Closing stdin is EOF to the command; leaving the `with`
        block only lets go of it."""
        self = cls.__new__(cls)
        self._setup(list(info.cmd), bool(encoding or errors or text), api_pb2.AttachInput)
        self._readers(PIPE, PIPE, -1, encoding, errors)
        self.cmd_id = info.cmd_id
        self.info = info
        self._attached = True
        sandbox = self._sandbox
        self._inputs = queue.Queue()
        self._inputs.put(
            api_pb2.AttachInput(
                start=api_pb2.AttachStart(
                    sandbox_id=sandbox.id, command_id=info.cmd_id, from_offset=from_offset
                )
            )
        )
        call = sandbox._transport.route(sandbox.id).duplex("Attach", _drain(self._inputs), None)
        self._pump_in_background(call, None)
        self._pipe_stdin(-1, encoding, errors)
        return self

    def _setup(self, args: Any, text_mode: bool, message: Any) -> None:
        self.args = args
        self.text_mode = text_mode
        self.pid = None
        self.returncode: Optional[int] = None
        self.cmd_id = ""
        # Burrow's own: bytes of output the node no longer had to replay, or
        # never recorded. Only an attach reports any.
        self.lost_bytes = 0
        self.stdin: Any = None
        # ExecInput or AttachInput: the stdin fields are the same on both.
        self._message = message
        self._attached = False
        self._detached = False
        self._status: Optional[int] = None
        self._error: Optional[BaseException] = None
        self._done = threading.Event()
        self._communication_started = False

    def _readers(
        self, stdout: Any, stderr: Any, bufsize: int, encoding: Optional[str], errors: Optional[str]
    ) -> None:
        out_sink, self.stdout = self._reader(stdout, 1, bufsize, encoding, errors)
        if stderr == STDOUT:
            err_sink, self.stderr = out_sink, None
        else:
            err_sink, self.stderr = self._reader(stderr, 2, bufsize, encoding, errors)
        self._sinks = {"stdout": out_sink, "stderr": err_sink}

    def _reader(
        self, target: Any, inherited: int, bufsize: int, encoding: Optional[str], errors: Optional[str]
    ) -> Tuple[Any, Any]:
        """Where one output stream goes, and the file the caller reads it
        from when that is a pipe."""
        if target == PIPE:
            raw = _OutputPipe()
            reader = _buffered(raw, io.BufferedReader, bufsize)
            if self.text_mode:
                reader = io.TextIOWrapper(reader, encoding=encoding or "utf-8", errors=errors)
            return raw, reader
        if target == DEVNULL:
            return None, None
        if target is None:
            return inherited, None
        return (target if isinstance(target, int) else target.fileno()), None

    def _pipe_stdin(self, bufsize: int, encoding: Optional[str], errors: Optional[str]) -> None:
        self.stdin = _buffered(_InputPipe(self), io.BufferedWriter, bufsize)
        if self.text_mode:
            self.stdin = io.TextIOWrapper(
                self.stdin,
                write_through=True,
                line_buffering=bufsize == 1,
                encoding=encoding or "utf-8",
                errors=errors,
            )

    def _send(self, **fields: Any) -> None:
        self._inputs.put(self._message(**fields))

    def _feed(self, fd: int) -> None:
        while True:
            data = os.read(fd, _STDIN_CHUNK)
            if not data:
                break
            self._send(stdin=data)
        self._send(is_stdin_eof=True)

    def _pump_in_background(self, call: Any, first: Any) -> None:
        self._call = call
        threading.Thread(target=self._pump, args=(call, first), daemon=True).start()

    def _pump(self, call: Any, first: Any) -> None:
        signal_number = 0
        try:
            for msg in itertools.chain(() if first is None else (first,), call):
                kind = msg.WhichOneof("output")
                if kind in ("stdout", "stderr"):
                    sink = self._sinks[kind]
                    if isinstance(sink, int):
                        _write_fd(sink, getattr(msg, kind))
                    elif sink is not None:
                        sink.feed(getattr(msg, kind))
                elif kind == "exit_signal":
                    signal_number = msg.exit_signal
                elif kind == "exit_code":
                    # POSIX Popen reports a signal exit as minus the signal,
                    # where the wire carries the shell's 128 plus it.
                    self._status = (
                        -_from_linux_signal(signal_number) if signal_number else msg.exit_code
                    )
                elif kind == "lost_bytes":
                    self.lost_bytes += msg.lost_bytes
        except grpc.RpcError as err:
            if not call.cancelled():
                self._error = BurrowError.from_grpc(err)
        except OSError as err:
            self._error = err
            call.cancel()
        finally:
            # Ends the request side, which nothing will write to again; left
            # open it would strand the thread sending it.
            self._inputs.put(None)
            for sink in self._sinks.values():
                if isinstance(sink, _OutputPipe):
                    sink.finish()
            self._done.set()

    def poll(self) -> Optional[int]:
        if self.returncode is None and self._done.is_set():
            self.wait()
        return self.returncode

    def wait(self, timeout: Optional[float] = None) -> int:
        if self.returncode is not None:
            return self.returncode
        if not self._done.wait(timeout):
            raise TimeoutExpired(self.args, timeout)
        if self._status is None:
            raise self._error or BurrowError(
                f"the stream for command {self.cmd_id} ended without an exit status",
                "unavailable",
            )
        self.returncode = self._status
        return self.returncode

    def communicate(self, input: Any = None, timeout: Optional[float] = None) -> Tuple[Any, Any]:
        """`Popen.communicate`. Output is collected by the reading thread
        whether or not anything waits for it, so a call that times out loses
        none of it: the next call returns everything."""
        if self._communication_started and input:
            raise ValueError("Cannot send input after starting communication")
        if self.stdin and not self._communication_started:
            try:
                if input:
                    self.stdin.write(input)
            except BrokenPipeError:
                pass
            try:
                self.stdin.close()
            except BrokenPipeError:
                pass
        self._communication_started = True
        if not self._done.wait(timeout):
            raise TimeoutExpired(self.args, timeout)
        stdout = self.stdout.read() if self.stdout else None
        stderr = self.stderr.read() if self.stderr else None
        if self.stdout:
            self.stdout.close()
        if self.stderr:
            self.stderr.close()
        self.wait()
        return stdout, stderr

    def send_signal(self, sig: int) -> None:
        self._signal(_to_linux_signal(sig))

    def terminate(self) -> None:
        self._signal(_LINUX_SIGNALS["SIGTERM"])

    def kill(self) -> None:
        self._signal(_LINUX_SIGNALS["SIGKILL"])

    def _signal(self, linux_signal: int) -> None:
        # A command known to have exited is left alone, as the stdlib does.
        self.poll()
        if self.returncode is not None:
            return
        try:
            self._sandbox._signal_command(self.cmd_id, linux_signal)
        except BurrowError as err:
            # Exited between the poll and the signal: what the signal was for.
            if not err.is_already_exited:
                raise

    def __enter__(self) -> "Popen":
        return self

    def __exit__(self, exc_type: Any, value: Any, traceback: Any) -> None:
        if self._attached:
            # Not this handle's command to end: it lets go of the stream and
            # leaves the command, and its stdin, as they were.
            self._detached = True
            for stream in (self.stdout, self.stderr, self.stdin):
                stream.close()
            self._call.cancel()
            return
        if self.stdout:
            self.stdout.close()
        if self.stderr:
            self.stderr.close()
        try:
            if self.stdin:
                self.stdin.close()
        finally:
            self.wait()

    def __repr__(self) -> str:
        return f"<{type(self).__name__}: returncode: {self.returncode} args: {self.args!r}>"


class SandboxSubprocess:
    """`subprocess`, for the sandbox. See `Popen` for where it differs."""

    PIPE = PIPE
    STDOUT = STDOUT
    DEVNULL = DEVNULL
    CompletedProcess = CompletedProcess
    CalledProcessError = CalledProcessError
    TimeoutExpired = TimeoutExpired
    SubprocessError = SubprocessError

    def __init__(self, sandbox: "Sandbox"):
        self.Popen = type("Popen", (Popen,), {"_sandbox": sandbox})

    def run(
        self,
        *popenargs: Any,
        input: Any = None,
        capture_output: bool = False,
        timeout: Optional[float] = None,
        check: bool = False,
        **kwargs: Any,
    ) -> subprocess.CompletedProcess:
        if input is not None:
            if kwargs.get("stdin") is not None:
                raise ValueError("stdin and input arguments may not both be used.")
            kwargs["stdin"] = PIPE
        if capture_output:
            if kwargs.get("stdout") is not None or kwargs.get("stderr") is not None:
                raise ValueError("stdout and stderr arguments may not be used with capture_output.")
            kwargs["stdout"] = PIPE
            kwargs["stderr"] = PIPE
        with self.Popen(*popenargs, **kwargs) as process:
            try:
                stdout, stderr = process.communicate(input, timeout=timeout)
            except TimeoutExpired as exc:
                process.kill()
                # Nothing the command printed was lost to the timeout, so the
                # exception carries all of it, decoded as the call asked.
                exc.stdout, exc.stderr = process.communicate()
                raise
            except BaseException:
                process.kill()
                raise
            retcode = process.poll()
            if check and retcode:
                raise CalledProcessError(retcode, process.args, output=stdout, stderr=stderr)
        return CompletedProcess(process.args, retcode, stdout, stderr)

    def call(self, *popenargs: Any, timeout: Optional[float] = None, **kwargs: Any) -> int:
        with self.Popen(*popenargs, **kwargs) as p:
            try:
                return p.wait(timeout=timeout)
            except BaseException:
                p.kill()
                raise

    def check_call(self, *popenargs: Any, **kwargs: Any) -> int:
        retcode = self.call(*popenargs, **kwargs)
        if retcode:
            cmd = kwargs.get("args")
            if cmd is None:
                cmd = popenargs[0]
            raise CalledProcessError(retcode, cmd)
        return 0

    def check_output(self, *popenargs: Any, timeout: Optional[float] = None, **kwargs: Any) -> Any:
        for kw in ("stdout", "check"):
            if kw in kwargs:
                raise ValueError(f"{kw} argument not allowed, it will be overridden.")
        if "input" in kwargs and kwargs["input"] is None:
            text = (
                kwargs.get("universal_newlines")
                or kwargs.get("text")
                or kwargs.get("encoding")
                or kwargs.get("errors")
            )
            kwargs["input"] = "" if text else b""
        return self.run(*popenargs, stdout=PIPE, timeout=timeout, check=True, **kwargs).stdout

    def getstatusoutput(
        self, cmd: Any, *, encoding: Optional[str] = None, errors: Optional[str] = None
    ) -> Tuple[int, str]:
        try:
            data = self.check_output(
                cmd, shell=True, text=True, stderr=STDOUT, encoding=encoding, errors=errors
            )
            exitcode = 0
        except CalledProcessError as ex:
            data = ex.output
            exitcode = ex.returncode
        if data[-1:] == "\n":
            data = data[:-1]
        return exitcode, data

    def getoutput(
        self, cmd: Any, *, encoding: Optional[str] = None, errors: Optional[str] = None
    ) -> str:
        return self.getstatusoutput(cmd, encoding=encoding, errors=errors)[1]
