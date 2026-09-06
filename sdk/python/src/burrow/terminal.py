"""An interactive shell in a sandbox."""

from __future__ import annotations

import queue
import threading
from typing import Any, Callable, Dict, Iterator, List, Optional, Union

import grpc

from ._pb import api_pb2
from ._transport import Transport
from .errors import BurrowError


class Terminal:
    """A live shell in a sandbox.

    Unlike `Sandbox.exec`, the input side stays open: the caller writes
    keystrokes and resizes as they happen. That is what makes this usable
    behind a WebSocket, where a browser terminal is on the other end.

    ```python
    term = sandbox.terminal(cols=120, rows=40)
    term.on_data(lambda chunk: ws.send(chunk))
    term.write("ls -la\\n")
    term.wait()
    ```

    Output callbacks are delivered from a background reader thread.
    """

    def __init__(self, transport: Transport, sandbox_id: str, options: Dict[str, Any]):
        command = options.get("command") or "/bin/sh"
        cmd = [command] if isinstance(command, str) else list(command)

        self._exited = threading.Event()
        self._exit_code = 0
        self._error: Optional[Exception] = None
        self._on_data: List[Callable[[str], Any]] = []
        self._on_exit: List[Callable[[int], Any]] = []
        self._on_error: List[Callable[[Exception], Any]] = []

        self._inputs: "queue.Queue[Optional[api_pb2.ExecInput]]" = queue.Queue()
        self._inputs.put(
            api_pb2.ExecInput(
                start=api_pb2.ExecStart(
                    sandbox_id=sandbox_id,
                    cmd=cmd,
                    env=options.get("env") or {},
                    cwd=options.get("cwd") or "",
                    pty=True,
                    rows=options.get("rows") or 24,
                    cols=options.get("cols") or 80,
                )
            )
        )

        def requests() -> Iterator[api_pb2.ExecInput]:
            while True:
                item = self._inputs.get()
                if item is None:
                    return
                yield item

        # A shell outlives any request deadline.
        self._call = transport.duplex("Exec", requests(), None)
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        try:
            for msg in self._call:
                kind = msg.WhichOneof("output")
                if kind == "stdout" and msg.stdout:
                    self._emit_data(msg.stdout.decode("utf-8", "replace"))
                elif kind == "stderr" and msg.stderr:
                    # A pty merges stderr into stdout, so anything arriving
                    # here came from a non-pty program; it is still terminal
                    # output to the reader.
                    self._emit_data(msg.stderr.decode("utf-8", "replace"))
                elif kind == "exit_code":
                    self._finish(msg.exit_code)
            self._finish(0)
        except grpc.RpcError as err:
            if not self._exited.is_set():
                self._error = BurrowError.from_grpc(err)
                for listener in self._on_error:
                    listener(self._error)
                self._exited.set()

    def _emit_data(self, chunk: str) -> None:
        for listener in self._on_data:
            listener(chunk)

    def _finish(self, exit_code: int) -> None:
        if self._exited.is_set():
            return
        self._exit_code = exit_code
        for listener in self._on_exit:
            listener(exit_code)
        self._exited.set()

    def write(self, data: Union[str, bytes]) -> None:
        """Sends keystrokes to the terminal."""
        if self._exited.is_set():
            return
        payload = data.encode("utf-8") if isinstance(data, str) else data
        self._inputs.put(api_pb2.ExecInput(stdin=payload))

    def resize(self, rows: int, cols: int) -> None:
        """Tells the program its window changed size."""
        if self._exited.is_set():
            return
        self._inputs.put(
            api_pb2.ExecInput(resize=api_pb2.ExecResize(rows=rows, cols=cols))
        )

    def signal(self, signal: int) -> None:
        """Sends a signal, e.g. 2 for SIGINT (Ctrl-C at the process level)."""
        if self._exited.is_set():
            return
        self._inputs.put(api_pb2.ExecInput(signal=signal))

    def on_data(self, listener: Callable[[str], Any]) -> "Terminal":
        """Subscribes to terminal output."""
        self._on_data.append(listener)
        return self

    def on_exit(self, listener: Callable[[int], Any]) -> "Terminal":
        self._on_exit.append(listener)
        return self

    def on_error(self, listener: Callable[[Exception], Any]) -> "Terminal":
        self._on_error.append(listener)
        return self

    def wait(self, timeout: Optional[float] = None) -> int:
        """Blocks until the program ends and returns its exit code."""
        if not self._exited.wait(timeout):
            raise BurrowError("terminal did not exit in time", "deadline_exceeded")
        if self._error is not None:
            raise self._error
        return self._exit_code

    def end(self) -> None:
        """Closes the input side, as a terminal does on Ctrl-D."""
        if not self._exited.is_set():
            self._inputs.put(None)

    def kill(self) -> None:
        """Terminates the program and tears the stream down."""
        self._exited.set()
        self._inputs.put(None)
        self._call.cancel()

    def __enter__(self) -> "Terminal":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.kill()
