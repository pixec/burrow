# burrow Python SDK

Python SDK for [burrow](../../README.md): run untrusted code in Firecracker
microVM sandboxes.

```python
from burrow import Sandbox

sandbox = Sandbox.create(template="python")
result = sandbox.subprocess.run(
    ["python3", "-c", "print(1 + 1)"], capture_output=True, text=True
)
print(result.stdout)  # "2\n"
sandbox.delete()
```

Or scoped, so the sandbox is destroyed when the block ends:

```python
with Sandbox.create(template="python") as sandbox:
    sandbox.subprocess.run("pip install cowsay", shell=True, check=True)
```

Files and processes in the sandbox are reached through the standard library's
own APIs, bound to it: `sandbox.open`, `sandbox.os` (with `sandbox.os.path`),
`sandbox.shutil`, `sandbox.Path` and `sandbox.subprocess`. Anyone who knows
`open()`, `os`, `shutil`, `pathlib` and `subprocess` already knows them: the
same names, signatures, return types and exceptions, with the guest's
filesystem and processes underneath, and one way to do each thing. Policies,
snapshots, volumes, templates, ports and private networks behave as in the
[TypeScript SDK](../typescript/README.md), which documents them in more depth.

## Install

```sh
pip install pixec-burrow
```

Configuration comes from arguments or the environment:

```python
Sandbox.create(template="python", endpoint="https://burrow.example.com", api_key="...")
# or BURROW_ENDPOINT / BURROW_API_KEY
```

An API key over a plaintext connection to anything but localhost is refused
unless `tls=False` (or an `http://` scheme) says it is intended.

## Files

```python
with sandbox.open("/work/app.py", "w") as f:
    f.write("print('hi')\n")

work = sandbox.Path("/work")
(work / "data.csv").write_text("a,b\n1,2\n")
for path in work.iterdir():
    print(path.name, path.stat().st_size)

sandbox.os.makedirs("/work/out", exist_ok=True)
sandbox.shutil.copytree("/work", "/backup")
try:
    sandbox.os.remove("/work/missing")
except FileNotFoundError as err:
    print("no such file:", err.filename)
```

- `sandbox.open(file, mode="r", buffering=-1, encoding=None, errors=None,
  newline=None)` is builtin `open()`: a raw file over the guest's handle in the
  stdlib's own `io.BufferedReader`, `BufferedWriter`, `BufferedRandom` and
  `TextIOWrapper`, so modes `r w x a + b t`, readline, iteration, newline
  translation, `seek`/`tell` and `with` behave exactly as they do locally.
  Reads and writes travel in calls of at most 4 MiB; the buffering layer
  splits and joins them.
- `sandbox.os`: `stat`, `lstat` (real `os.stat_result`s, float and `_ns`
  times included), `listdir`, `scandir`, `walk`, `mkdir`, `makedirs`,
  `remove`, `unlink`, `rmdir`, `removedirs`, `rename`, `replace`, `chmod`,
  `chown`, `lchown`, `link`, `symlink`, `readlink`, `utime`, `truncate`,
  `access` with `F_OK`, `R_OK`, `W_OK`, `X_OK`.
- `sandbox.os.path`: `exists`, `lexists`, `isfile`, `isdir`, `islink`,
  `getsize`, `getmtime`, `getatime`, `getctime`, `realpath`, `samefile`, and
  `posixpath`'s pure functions (`join`, `basename`, `dirname`, `split`,
  `splitext`, `normpath`, ...), since the guest is Linux whatever this machine
  is.
- `sandbox.shutil`: `copyfile`, `copy`, `copy2`, `copymode`, `copystat`,
  `copytree`, `rmtree`, `move`, raising `shutil.Error` and
  `shutil.SameFileError`. The guest copies a file's bytes itself, and removes a
  tree in one call, rather than streaming them through the client.
- `sandbox.Path` is a `pathlib.PurePosixPath` subclass bound to the sandbox:
  `/`, `parent` and the other pure operations return bound paths, and it has
  `pathlib.Path`'s `exists`, `is_dir`, `is_file`, `is_symlink`, `stat`,
  `lstat`, `open`, `read_text`, `read_bytes`, `write_text`, `write_bytes`,
  `iterdir`, `mkdir`, `touch`, `unlink`, `rmdir`, `rename`, `replace`,
  `chmod`, `symlink_to`, `hardlink_to`, `readlink`, `resolve` and `samefile`.
  It is still an `os.PathLike`, so the local `open(path)` opens a local file.

A failure in the guest kernel raises exactly what the stdlib raises:
`OSError(errno, strerror, filename[, filename2])`, as the subclass its errno
names (`FileNotFoundError`, `FileExistsError`, `PermissionError`,
`IsADirectoryError`, `NotADirectoryError`, ...). The guest's Linux errno is
matched by name to this platform's, so the right subclass is picked on macOS
too. The file policy refuses the way the kernel would: a path outside its
scopes, or uploads or downloads turned off, is `PermissionError`, and a write
past `max_upload_bytes` is `OSError` with `errno.EFBIG`. Exec refused by
policy raises `BurrowError`.

Where it differs from the stdlib, and why:

- Text defaults to UTF-8, not this machine's locale encoding: the file is the
  guest's.
- `buffering=-1` buffers 1 MiB rather than `st_blksize`, since each refill
  is a round trip.
- `fileno()` raises `io.UnsupportedOperation`, as `BytesIO` does: a handle is
  not a local descriptor, and code that handed one to a local syscall would
  act on an unrelated local file.
- Opening a directory read-only fails at the first read (`IsADirectoryError`)
  rather than at `open()`, which saves a stat on every open.
- `utime(path)` with no times reads now from this machine's clock.
- `dir_fd`, `chmod(follow_symlinks=False)`, and anything that reads this
  process's state (`abspath`, `relpath`, `expanduser`, `getcwd`) are not
  offered. `Path` has no `owner`, `group`, `glob`, `walk` or `absolute`.
- Paths are the guest's: relative ones resolve against the guest agent's
  working directory.

## Commands

```python
sp = sandbox.subprocess
out = sp.check_output(["git", "rev-parse", "HEAD"], cwd="/work", text=True)

with sp.Popen(["python3", "-u", "train.py"], stdout=sp.PIPE, text=True) as proc:
    for line in proc.stdout:
        print(line, end="")

try:
    sp.run("pytest -q", shell=True, check=True, timeout=600)
except sp.CalledProcessError as err:
    print("failed with", err.returncode)
```

`sandbox.subprocess` is the `subprocess` module over burrow's exec stream:
`run`, `call`, `check_call`, `check_output`, `getoutput`, `getstatusoutput`
and `Popen`, with the stdlib's own `PIPE`, `STDOUT`, `DEVNULL`,
`CompletedProcess`, `CalledProcessError`, `TimeoutExpired` and
`SubprocessError`. A string is the program unless `shell=True` hands it to
`/bin/sh -c`; `stderr=STDOUT` merges; a timeout kills the command and raises
`TimeoutExpired`; a command a signal ended has `returncode` minus the signal,
as POSIX `Popen` reports it. Signal numbers cross by name, so
`proc.send_signal(signal.SIGUSR1)` sends the guest's SIGUSR1 from macOS too.
`Popen` has `stdin`, `stdout` and `stderr` files for `PIPE` (text or bytes by
`text`/`encoding`), `args`, `returncode`, `poll`, `wait`, `communicate`,
`send_signal`, `terminate`, `kill` and `with`.

Where it differs, because the command is not this process's child:

- `stdin=None` is EOF in the guest, rather than this process's stdin.
  `stdout=None` and `stderr=None` do inherit: output goes to this process's
  descriptors 1 and 2. A local descriptor or file works for all three.
- Output is read off the stream as it arrives and held until read, rather than
  blocking the command when a pipe fills. A `communicate` that times out loses
  nothing, and the `TimeoutExpired` from `run` carries everything printed,
  decoded as the call asked.
- `env` is laid over the guest's environment and the handle's `env=`, rather
  than replacing it.
- `pid` is `None`: the guest does not expose it. `cmd_id` names the command
  instead.
- `user` names a guest user. Text mode decodes UTF-8 by default.
- Popen arguments with no meaning here (`executable`, `preexec_fn`,
  `close_fds`, `pass_fds`, `start_new_session`, `group`, `umask`, ...) are
  not taken.

Burrow's own `Popen` arguments, with no stdlib counterpart: `pty=True` runs the
command on a terminal; `log_max_bytes` and `log_max_files` rotate the log the
node keeps of its output, as Docker's `--log-opt max-size` and `max-file`
(unset keeps every byte).

A command outlives the process that started it, and so does every byte it
prints, kept on the node the way Docker keeps a container's log.
`sandbox.list_commands()` lists them, `sandbox.prune_commands()` removes the
finished ones and their output, as `docker container prune`, and
`sandbox.get_command(cmd_id, from_offset=0)` returns a `Popen` attached to one
from anywhere: its `stdout` and `stderr` replay from the offset a reader got
to, counting both streams' bytes together, then follow live; `stdin` feeds it,
a shell whose original stream is long gone included; `kill()` and `wait()`
work. Leaving its `with` block lets go without ending the command or its
stdin. `lost_bytes` counts output a rotating log dropped.

## Everything else

- `Sandbox`: `create`, `get`, `get_or_create`, `list`, `fork`; `watch` for a
  directory's changes; `terminal()` for a live pty; ports (`expose_port`,
  `domain`, `share`); updates (`update_tags`, `update_network_policy`,
  `update_access_policy`, `update_resources`); lifecycle (`stop`, `resume`,
  `shutdown`, `boot`, `recreate`, `move`, `snapshot`, `delete`); guest users
  (`create_user`, `create_group`, `as_user`). `as_user(name)` returns a handle
  whose `open`, `os`, `shutil`, `Path`, `subprocess` and `terminal` act as
  that user, with the guest kernel deciding what they may touch. A `kit=`
  argument to `create` carries `args`, `env` and `reject_capabilities` for a
  Sandbox Kit template.
- `network_policy` is a mode (`"none"`, `"allowlist"`, `"open"`) or the full
  policy as a dict: `mode`, `allow_domains`, `allow_cidrs`, `allow_ports`,
  `deny_cidrs`, `inspect_tls` and `rules`. A key burrow does not know is
  refused rather than dropped, on the policy and on each rule.
- `Burrow`: the fleet: `health`, `audit`, `events`, `nodes`, `drain_node`, and the secrets Sandbox Kits ask
  for by service name: `set_secret`, `list_secrets`, `delete_secret`.
  `events` reads the fleet's lifecycle log, oldest first, and with
  `follow=True` keeps yielding new events as they happen:

  ```python
  for event in burrow.events(sandbox="build-482", follow=True):
      print(event.seq, event.type, event.state, event.detail)
  ```

  Pass the last `seq` seen as `after=` to resume after a disconnect.
- `Snapshot`, `Volume`: saved state and persistent storage, addressable on
  their own. A snapshot reports `is_durable` once a copy is in the fleet's
  object store, and the `arch` and `firecracker_version` a node needs to
  restore it.
- `Template`: build guest images by running steps in a sandbox:

  ```python
  from burrow import Template, default_build_logger

  template = Template().from_image("python:3.12-slim").pip_install(["requests"])
  Template.build(template, "python-tools", on_build_logs=default_build_logger())
  ```

  `systemd=True` boots the image's own systemd under the agent;
  `Template.list()` reports it as `systemd`.

- `Terminal`: a live pty for interactive use, callback-driven:

  ```python
  term = sandbox.terminal(cols=120, rows=40)
  term.on_data(print)
  term.write("ls\n")
  ```

Exec, attach and `Fs` calls go to the node holding the sandbox by default,
with a token the SDK gets from the orchestrator and reuses until it nears
expiry; the node has to be reachable from where the SDK runs. Pass
`route="orchestrator"` (or set `BURROW_ROUTE=orchestrator`) and the
orchestrator relays them instead. Neither falls back to the other. Everything
else goes to the orchestrator.

`examples/quickstart.py` tours the lot against a running stack.

Earlier spellings are gone. Commands: `exec`, `exec_stream` and `spawn`
(use `subprocess.run` and `subprocess.Popen`), and `CommandResult`,
`OutputChunk`, `DetachedCommand` and `CommandFailedError` with them. Files:
`write_file`, `write_files`, `read_file`, `read_file_bytes`, `open_file`,
`download_file`, `list_dir`, `mkdir`, `remove`, `rename`, `stat` and `exists`
(use `open`, `os`, `shutil` and `Path`). Network policy: the `"allow-all"`
and `"deny-all"` strings (use `"open"` and `"none"`) and the
`{"allow": ..., "subnets": ...}` shorthand (use the full policy).

## Development

Generated gRPC code is committed under `src/burrow/_pb`. After a `.proto`
changes (`scripts/sync-protos.sh` refreshes the copies here):

```sh
pip install -e '.[dev]'
python scripts/genproto.py
pytest
```
