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
for semantics — policies, snapshots, volumes, templates, ports and private
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

- `Sandbox` — create/get/get_or_create/list/fork, `run_command`/`exec`/
  `exec_stream`, files (`write_files`, `read_file`, `download_file`,
  `list_dir`, `watch`), ports (`expose_port`, `domain`), policy updates
  (`update`, `update_network_policy`, `update_access_policy`), lifecycle
  (`stop`, `resume`, `snapshot`, `delete`), guest users (`create_user`,
  `as_user`).
- `Burrow` — one connection for many sandboxes: `health`, `list`, `get`,
  `audit`, `nodes`, `drain_node`.
- `Snapshot`, `Volume` — saved state and persistent storage, addressable on
  their own.
- `Template` — build guest images by running steps in a sandbox:

  ```python
  from burrow import Template, default_build_logger

  template = Template().from_image("python:3.12-slim").pip_install(["requests"])
  Template.build(template, "python-tools", on_build_logs=default_build_logger())
  ```

- `Terminal` — a live pty for interactive use, callback-driven:

  ```python
  term = sandbox.terminal(cols=120, rows=40)
  term.on_data(print)
  term.write("ls\n")
  ```

`examples/quickstart.py` tours the lot against a running stack.

## Development

Generated gRPC code is committed under `src/burrow/_pb`. After a `.proto`
changes (`cargo xtask protos` refreshes the copies here):

```sh
pip install -e '.[dev]'
python scripts/genproto.py
pytest
```
