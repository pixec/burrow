# burrow Python SDK

Python SDK for [burrow](../../README.md): run untrusted code in Firecracker
microVM sandboxes.

```python
from burrow import Sandbox

sandbox = Sandbox.create(template="python")
result = sandbox.run_command("python3", ["-c", "print(1 + 1)"])
print(result.stdout)  # "2\n"
sandbox.delete()
```

Or scoped, so the sandbox is destroyed when the block ends:

```python
with Sandbox.create(template="python") as sandbox:
    sandbox.exec("pip install cowsay")
```

The API mirrors the [TypeScript SDK](../typescript/README.md) with Python
naming: `runCommand` is `run_command`, options objects are keyword arguments,
and blocking calls return rather than resolve. That README is the reference
for semantics: policies, snapshots, volumes, templates, ports and private
networks all behave identically; only the spelling differs.

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

## The pieces

- `Sandbox`: create/get/get_or_create/list/fork, `run_command`/`exec`/
  `exec_stream`, files (`write_files`, `read_file`, `download_file`,
  `list_dir`, `watch`), ports (`expose_port`, `domain`), policy updates
  (`update`, `update_network_policy`, `update_access_policy`), lifecycle
  (`stop`, `resume`, `shutdown`, `boot`, `recreate`, `snapshot`, `delete`),
  guest users (`create_user`, `as_user`). A `kit=` argument to `create` carries
  `args`, `env` and `reject_capabilities` for a Sandbox Kit template.
- `sandbox.fs`: the file methods under the names and shapes of `os` and
  `pathlib`, so code written against those reads the same here: `listdir`,
  `mkdir`, `makedirs`, `remove`, `rmtree`, `rename`, `stat`, `exists`,
  `read_text`, `read_bytes`, `write_text`, `write_bytes`. As in `os`, `stat`
  on a missing path raises `not_found` and `remove` refuses a directory.
  `mkdir`, `remove` and `rename` run `mkdir`, `rm` and `mv` in the sandbox;
  `stat` and `exists` list the parent directory, so they respect the file
  policy and cost no exec. Watching has no `os` counterpart, so it stays
  `sandbox.watch`.
- `sandbox.commands` (`run`, `stream`, `list`, `connect`, `kill`) and
  `sandbox.pty.create()`, which is `sandbox.terminal`. A command outlives the
  process that started it, and so does every byte it prints, kept in the
  sandbox the way Docker keeps a container's log. `get_command(cmd_id,
  from_offset=n)` replays from the offset a reader got to, counting stdout and
  stderr bytes together, and `send_stdin` feeds a shell whose original stream
  is long gone. Chunks carry `raw`, the exact bytes, beside `data`, text decoded
  across chunk boundaries; a `"lost"` chunk says how many bytes a rotating log
  (`log_max_bytes`, `log_max_files`) dropped. An exit a signal caused reports
  `exit_signal`. `prune_commands()` removes finished commands and their output,
  as `docker container prune`.

Exec, attach and file calls go to the node holding the sandbox by default,
with a token the SDK gets from the orchestrator and reuses until it nears
expiry; the node has to be reachable from where the SDK runs. Pass
`route="orchestrator"` (or set `BURROW_ROUTE=orchestrator`) and the
orchestrator relays them instead. Neither falls back to the other. Everything
else goes to the orchestrator.
- `Burrow`: one connection for many sandboxes: `health`, `list`, `get`,
  `audit`, `events`, `nodes`, `drain_node`, and the secrets Sandbox Kits ask
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

`examples/quickstart.py` tours the lot against a running stack.

## Development

Generated gRPC code is committed under `src/burrow/_pb`. After a `.proto`
changes (`scripts/sync-protos.sh` refreshes the copies here):

```sh
pip install -e '.[dev]'
python scripts/genproto.py
pytest
```
