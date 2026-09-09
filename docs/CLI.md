# CLI reference

`burrow` drives the orchestrator over gRPC. Install it from the workspace:

```sh
cargo install --path crates/burrow-cli
```

Or run it straight from the checkout:

```sh
alias burrow='cargo run -q -p burrow-cli --'
```

## Global options

| Option | Description |
| --- | --- |
| `--orchestrator <URL>` | Orchestrator endpoint. Defaults to `http://127.0.0.1:7070`. Reads `BURROW_ORCHESTRATOR`. |
| `--api-key <TOKEN>` | Bearer token, when the orchestrator requires one. Reads `BURROW_API_KEY`. |
| `--api-key-file <PATH>` | Read the token from a file instead. First non-blank, non-`#` line. Reads `BURROW_API_KEY_FILE`. |
| `--insecure` | Allow a plaintext `http://` endpoint that is not on this machine. Reads `BURROW_INSECURE`. |
| `-h`, `--help` | Print help for the command. |

Set them once and leave them out of the examples below:

```sh
export BURROW_ORCHESTRATOR=http://127.0.0.1:7070
export BURROW_API_KEY=dev-token
```

Prefer `--api-key-file` on a shared machine: a token on a command line is
visible in `ps` output to every user on the host.

### Reaching a remote orchestrator

An `https://` endpoint is verified against the platform's own CA store:

```sh
burrow --orchestrator https://burrow.example.com:7070 ps
```

The api key travels in a header on every call, so `http://` to anything but
this machine is refused rather than quietly leaking it:

```
refusing to send the api key in plaintext to burrow.example.com: use https://,
or pass --insecure if the endpoint is reached over a network you trust
```

`--insecure` says the plaintext hop is over a network you trust: a private
link, or a tunnel that is already encrypting it. `http://127.0.0.1:7070` and
`http://localhost:7070` need no flag, since there is no network to eavesdrop
on.

## Ids and names

Every command that takes an `<ID>` also takes the name the sandbox was created
with.

```sh
burrow create --template python --name api
burrow exec api -- python3 -c 'print(1 + 1)'
burrow stop api
```

A name is 1 to 63 characters of lowercase letters, digits and `-`, and may not
start or end with `-`. It is unique across the fleet, so creating a second
sandbox under a name in use fails with `AlreadyExists`, and it is fixed once the
sandbox exists: there is no rename. Nothing generates one, so a sandbox created
without `--name` is addressed by its id alone.

References resolve as an id first and a name second. The two cannot collide,
because an id is `sbx_` followed by a uuid and a name may not contain an
underscore.

## Coming from Docker

| Docker | Burrow | Notes |
| --- | --- | --- |
| `docker run` | [`run`](#run) | Creates a sandbox, runs one command, and leaves the sandbox up. |
| `docker run -d` | [`run -d`](#run) | Starts the command and returns. |
| `docker create` | [`create`](#create) | Creates the sandbox and nothing else. |
| `docker ps` | [`ps`](#ps) | Running sandboxes. `-a` adds the rest. |
| `docker exec` | [`exec`](#exec) | |
| `docker exec -it <c> sh` | [`connect`](#connect) | `exec --pty` with `/bin/sh` as the default command. |
| `docker top` | [`top`](#top) | The commands a sandbox has run. |
| `docker inspect` | [`inspect`](#inspect) | Readable fields by default, `--json` for the record. |
| `docker stats` | [`stats`](#stats) | Totals since creation, not a live meter. |
| `docker logs` | [`logs`](#logs) | Takes a command id as well as the sandbox. |
| `docker kill` | [`kill`](#kill) | Signals one command, never the sandbox. |
| `docker stop` | [`stop`](#stop) | Snapshots the VM to disk instead of killing it. |
| `docker start` | [`start`](#start) | Restores the snapshot the stop wrote. |
| `docker rm` | [`remove`](#remove) | |
| `docker commit` | [`commit`](#commit) | Saves live VM state, memory included. |
| `docker images` | [`images`](#images) | Templates, on the nodes. |
| `docker pull` | [`pull`](#pull) | Converts an OCI image into a template. There is no local image cache. |
| `docker rmi` | [`templates rm`](#templates-rm) | |
| `docker cp` | [`copy`](#copy) | |
| `docker port` | [`port`](#port) | |
| `docker version` | [`health`](#health) | |
| `docker node ls` | [`nodes ls`](#nodes-ls) | |

Three deviate on purpose:

- `logs` and `kill` take a command id. A sandbox is a machine, not a process, so
  it has no single stream of output and no single process to signal.
  [`top`](#top) is where you find the id.
- `inspect` prints readable fields by default, since most reads are a person
  checking what a sandbox is. `--json` is there when something parses it.
- `images` and `pull` are about templates, which live on the nodes as a rootfs a
  microVM boots. Nothing is cached locally, and there is no `docker push`
  equivalent.

No Docker counterpart at all: [`fork`](#fork), [`sessions`](#sessions),
[`expose`](#expose), [`audit`](#audit), [`user`](#user), [`group`](#group) and
[`config`](#config).

## Aliases

`burrow --help` and each command's own `--help` list these, except the two on
`snapshot` marked below, which are accepted but not advertised.

| Command | Also spelled |
| --- | --- |
| `ps` | `list`, `ls` |
| `connect` | `ssh`, `shell` |
| `copy` | `cp` |
| `stop` | `pause` |
| `start` | `resume` |
| `remove` | `rm` |
| `port` | `ports` |
| `snapshot` | `snapshots` |
| `snapshot ls` | `snapshot list` (hidden) |
| `snapshot rm` | `snapshot delete` (hidden) |
| `--pty` | `--tty` |

## Command summary

| Command | Does |
| --- | --- |
| [`health`](#health) | Check that the orchestrator answers |
| [`create`](#create) | Create a sandbox |
| [`run`](#run) | Create a sandbox and run one command in it |
| [`ps`](#ps) | List sandboxes |
| [`top`](#top) | List the commands a sandbox has run |
| [`inspect`](#inspect) | Print one sandbox's whole record |
| [`stats`](#stats) | Show what sandboxes have consumed |
| [`exec`](#exec) | Run a command in an existing sandbox |
| [`connect`](#connect) | Open an interactive shell |
| [`logs`](#logs) | Replay and follow a command's output |
| [`kill`](#kill) | Signal a running command |
| [`user`](#user) | Create guest users |
| [`group`](#group) | Create guest groups and manage membership |
| [`copy`](#copy) | Copy a file in or out |
| [`dir`](#dir) | List a directory inside a sandbox |
| [`stop`](#stop) | Snapshot a sandbox and stop its VM |
| [`start`](#start) | Restore a stopped sandbox |
| [`sessions`](#sessions) | List the VMs a sandbox has run |
| [`commit`](#commit) | Save a sandbox's state as a snapshot |
| [`snapshot`](#snapshot) | List and delete snapshots |
| [`fork`](#fork) | Create a sandbox from another's state |
| [`remove`](#remove) | Destroy sandboxes |
| [`config`](#config) | Read and replace a sandbox's configuration |
| [`expose`](#expose) | Publish a guest port |
| [`port`](#port) | List published ports |
| [`unexpose`](#unexpose) | Withdraw a published port |
| [`share`](#share) | Share a sandbox through a tailcat address |
| [`unshare`](#unshare) | Revoke a share |
| [`images`](#images) | List templates |
| [`pull`](#pull) | Import an OCI image as a template |
| [`templates`](#templates) | Manage templates |
| [`audit`](#audit) | Show egress attempts and DNS lookups |
| [`nodes`](#nodes) | Inspect and drain nodes |

## health

Check that the orchestrator answers, and print its version.

```
burrow health
```

```sh
burrow health
# ok (orchestrator v0.1.0)
```

## create

Create a sandbox and print its id. It runs until something deletes it, unless
you give it a lifetime.

```
burrow create [OPTIONS]
```

```sh
burrow create --template python --vcpus 2 --mem-mib 2048 --tag env=staging
# sbx_2f0c1c1a9f0c4b3f8f0f0b9c6a1d2e3f

burrow create --template python --name api
# sbx_b4929ded8342487abacca17105aa0def (api)
```

| Option | Description |
| --- | --- |
| `--name <NAME>` | Name for the sandbox, usable anywhere its id is. Unique, and fixed once the sandbox exists. |
| `--template <NAME>` | Template to boot, as imported by `burrow pull`. Required unless `--snapshot` is given. |
| `--snapshot <SNAPSHOT>` | Restore from a [snapshot](#snapshot) instead of booting. Takes its template and machine shape from the snapshot. |
| `--snapshot-expiration-secs <SECS>` | Sweep this sandbox's snapshots this long after they were last used. 0 (default) keeps them. |
| `--keep-last-snapshots <N>` | Keep only this many snapshots of the sandbox, evicting the oldest. 1 to 10; 0 (default) is unlimited. |
| `--keep-evicted-snapshots` | Let an evicted snapshot live out its expiration instead of being deleted at once. Requires `--keep-last-snapshots` and `--snapshot-expiration-secs`. |
| `--vcpus <N>` | vCPUs. Defaults to 1. |
| `--mem-mib <MIB>` | Memory in MiB. Defaults to 512. |
| `--max-lifetime-secs <SECS>` | Destroy the sandbox this long after it is created. 0 (default) never does. |
| `--idle-suspend-secs <SECS>` | Suspend the sandbox after this long without use. 0 (default) never does. |
| `--suspended-ttl-secs <SECS>` | Delete the sandbox once it has been suspended this long. 0 (default) keeps it. |
| `--tag <KEY=VALUE>` | Tag to attach. Repeatable, up to 16. |
| `-p`, `--publish <PORT>` | Guest port to publish once the sandbox exists, as [`expose`](#expose) would. The node picks the host port. Repeatable. |
| `--node-label <KEY=VALUE>` | Only place this sandbox on a node carrying this label. Repeatable, and every one must match. |
| `--network <NAME>` | Private network to join. Repeatable. |
| `--alias <NAME>` | Name this sandbox answers to on its networks, as `<alias>.<network>.internal`. Defaults to the sandbox id. |
| `--connect` | Open an interactive shell once the sandbox is running. |
| `--net <MODE>` | Egress policy: `none` (default), `allowlist`, or `open`. |
| `--allow-domain <DOMAIN>` | Domain the sandbox may reach in allowlist mode. Repeatable. |
| `--allow-cidr <CIDR>` | Destination permitted at L3, bypassing the egress proxy. Repeatable. |
| `--allow-port <PORT>` | Port the `--allow-cidr` allowance is limited to. Repeatable. |
| `--deny-cidr <CIDR>` | Range the sandbox may never reach, in any mode. Repeatable. |
| `--inspect-tls` | Terminate the sandbox's TLS so the host inside the session is checked. Requires `--net allowlist`. |
| `--inject-header <DOMAIN:NAME=VALUE>` | Credential the host adds to every request for a domain. Requires `--inspect-tls`. Repeatable. |
| `--rule <JSON>` | Rule for inspected requests: a domain, an optional `match`, and either `setHeaders` or `forward`. Requires `--inspect-tls`. Evaluated in order, and before every `--inject-header`. Repeatable. |
| `--no-exec` | Refuse `exec`, `run` and `connect` against this sandbox. |
| `--no-upload` | Refuse uploads into this sandbox. |
| `--no-download` | Refuse downloads out of this sandbox. |
| `--fs-scope <PATH>` | Absolute path uploads, downloads and listings are confined to. Repeatable, up to 16. |
| `--max-upload-bytes <N>` | Largest single upload accepted. 0 (default) is unlimited. |

`-p` publishes at creation, so a server is reachable as soon as it is up. The
mapping is printed under the id:

```sh
burrow create -p 8000
# sbx_6d4f1b2c3d4e5f60718293a4b5c6d7e8
# http://8000-sbx_6d4f1b2c3d4e5f60718293a4b5c6d7e8.node.sandbox.local:7081/ -> guest :8000 (node:20000)
```

A port that cannot be published leaves the sandbox in place and exits nonzero.
The sandbox was created, and losing it over a port would lose work you did not
ask to lose.

`--node-label` is what burrow has instead of regions. Operators label their
machines with `burrowd serve --label rack=b7`, [`nodes ls`](#nodes-ls) shows what
each one carries, and a create naming labels is placed only on a node carrying
every one of them. Nothing carrying them all is an error naming the labels
nothing satisfies, never a placement somewhere else.

```sh
burrow create --node-label rack=b7 --node-label tier=dedicated
```

The network options are the same group [`config
network-policy`](#config-network-policy) takes, so a policy means the same thing
wherever you write it. See [FIREWALL.md](FIREWALL.md).

The five access options are enforced by the node, before anything reaches the
guest. Naming none of them leaves the sandbox able to do everything. Naming any
one of the four file options settles all four, so `--fs-scope /work` on its own
still allows uploads and downloads, confined to `/work`. Scopes are matched on
whole path components: `/data` admits `/data/in.csv` and refuses
`/database/dump.sql`, and a path carrying `..` is refused. All of them can be
changed on a live sandbox with [`config access`](#config-access). See
[CONCEPTS.md](CONCEPTS.md).

## run

Create a sandbox, run one command in it, and leave it running. The command's
exit status becomes the CLI's, and the new sandbox id goes to stderr so you can
pipe the command's own output.

```
burrow run [OPTIONS] -- <COMMAND> [ARGS...]
```

```sh
burrow run --template python --net allowlist --allow-domain pypi.org -- \
  python3 -c 'print(1 + 1)'
# sandbox sbx_2f0c1c1a9f0c4b3f8f0f0b9c6a1d2e3f
# 2
```

| Argument | Description |
| --- | --- |
| `<COMMAND> [ARGS...]` | Command to run, after `--`. Required. |

| Option | Description |
| --- | --- |
| `-d`, `--detach` | Start the command and return without following it. Conflicts with `--stop` and `--rm`. |
| `--stop` | Suspend the sandbox once the command exits. Conflicts with `--rm`. |
| `--rm` | Delete the sandbox once the command exits. |
| `-e`, `--env <KEY=VALUE>` | Environment variable for the command. Repeatable. |
| `-w`, `--workdir <DIR>` | Directory to run in. |
| `-t`, `--pty` | Allocate a pty. Also spelled `--tty`. |
| `-u`, `--user <NAME>` | Guest user to run as. Defaults to root. |
| create options | Every option [`create`](#create) takes except `--connect`, applied to the new sandbox. |

`--name` makes this get-or-create: the named sandbox is reused if it exists,
started first if it is stopped, and created under that name if it is not there.
Create options passed alongside a `--name` that already exists are ignored with a
warning, since none of them can be applied to a sandbox that is already running.
`--name` and `-p` are the exceptions: one is what was matched on, and the other
still applies.

```sh
burrow run --name build-482 --template python -- python3 -c 'print(1 + 1)'
# sandbox sbx_2f0c1c1a9f0c4b3f8f0f0b9c6a1d2e3f
# 2
burrow run --name build-482 -- python3 -c 'print(2 + 2)'
# 4
```

Without `--name`, every run builds a fresh sandbox.

### Detaching

`-d` starts the command and returns. The command id goes to stderr and the
sandbox id to stdout, so you can capture the sandbox and follow the command
afterwards:

```sh
burrow run -d --name trainer -- ./train.sh
# sandbox sbx_2f0c1c1a9f0c4b3f8f0f0b9c6a1d2e3f
# command cmd_3
# sbx_2f0c1c1a9f0c4b3f8f0f0b9c6a1d2e3f

burrow logs trainer cmd_3
```

The `sandbox` line appears when the run created the sandbox, as any run does;
only the last line is stdout.

Nothing is streamed and nothing is waited for, so `-d` exits 0 whatever the
command goes on to do. That is why it conflicts with `--rm` and `--stop`: both
act on the command's exit, which a detached run never sees.

## ps

List sandboxes, with their name, state, node, template, and tags. Aliased as
`list` and `ls`.

A bare `ps` shows running sandboxes only, as `docker ps` does. Creating, running
and stopping all count as running, because they are live machines. Suspended,
failed, destroyed and lost records need `-a`.

```
burrow ps [-a] [--tag <KEY=VALUE>]
```

```sh
burrow ps --tag env=staging
# SANDBOX      NAME    STATE     NODE      TEMPLATE   TAGS           CREATED
# sbx_2f0c...  api     running   node_a    python     env=staging    2026-09-02T07:55:39Z
```

| Option | Description |
| --- | --- |
| `-a`, `--all` | Include sandboxes that are not running: stopped, suspended, failed and lost ones. |
| `--tag <KEY=VALUE>` | Show only sandboxes carrying this tag. Matched exactly. |

An unnamed sandbox shows `-` in the name column. Nothing is hidden silently:
when every sandbox is stopped, the empty listing says how many there are and how
to see them.

```sh
burrow ps
# no running sandboxes; `burrow ps -a` shows the 1 that are not running
```

A state of `lost` means the node hosting that sandbox has missed its heartbeats.
The record is still there, but the last state the node reported is all anyone
knows, and calls against it fail until the node returns. You can still remove it.

## top

List the commands a sandbox has run, oldest first, running and finished alike.

```
burrow top <ID>
```

```sh
burrow top sbx_2f0c
# COMMAND    USER       STATE    CODE   CMD
# cmd_1      root       exited   0      /bin/sh -c pip install -r requirements.txt
# cmd_2      alice      running  -      /bin/sh -c ./train.sh
```

| Argument | Description |
| --- | --- |
| `<ID>` | Sandbox to list. |

`CODE` is the exit status of a finished command and `-` while it is still
running. This is where [`logs`](#logs) and [`kill`](#kill) get their command ids.

A command outlives the `exec` that started it, so one you started in another
terminal is listed here. The guest keeps the 64 most recent finished commands
and every running one; older finished commands are dropped.

## inspect

Print one sandbox's whole record: template, state, usage, resources, egress
policy, private networks, and tags.

```
burrow inspect [--json] <ID>
```

```sh
burrow inspect sbx_2f0c
# sandbox         sbx_2f0c
# state           running
# node            node_a
# template        default
# created         2026-09-02T07:57:51Z
# address         10.99.0.10
# cpu             5550ms
# network         557.9 KiB in / 557.8 KiB out
# vcpus           1 (default)
# mem-mib         512 (default)
# exec            denied
# upload          allowed
# download        denied
# fs-scope        /work
# net             allowlist
# allow-domain    pypi.org
# inspect-tls     yes
# inject-header   pypi.org:Authorization=<redacted>
# rule            api.example.com path^="/v1/" method=GET -> forward http://gate.internal:8080/ (secret <redacted>)
# tags            env=staging
```

| Argument | Description |
| --- | --- |
| `<ID>` | Sandbox to read. |

| Option | Description |
| --- | --- |
| `--json` | Emit the record as JSON instead of the readable field list. |

```sh
burrow inspect --json sbx_2f0c | jq .network.allow_domains
```

Brokered credentials come back redacted. The values stay on the host and are
never readable through the API.

`cpu` and `network` are what the sandbox has actually consumed, totalled across
every VM it has run. See [what is counted](ARCHITECTURE.md#usage-metering).

[`config list`](#config-list) prints the same thing and takes the same `--json`.

## stats

Show what sandboxes have consumed: cpu time and bytes in and out, totalled
across every VM each one has run.

```
burrow stats [-a] [<ID>]
```

```sh
burrow stats
# SANDBOX      NAME    STATE     CPU       NET I     NET O
# sbx_2f0c...  api     running   5550ms    557.9 KiB  557.8 KiB
```

| Argument | Description |
| --- | --- |
| `<ID>` | Sandbox to report on. Omitted covers every sandbox. |

| Option | Description |
| --- | --- |
| `-a`, `--all` | Include sandboxes that are not running. Applies to the listing only. |

This is not a live meter. Each figure is a total since the sandbox was created,
so a stopped sandbox still reports what it spent while it ran. Naming an id
reports that sandbox whatever state it is in.

## exec

Run a command in an existing sandbox. The command's exit status becomes the
CLI's.

```
burrow exec [OPTIONS] <ID> -- <COMMAND> [ARGS...]
```

```sh
burrow exec -e TOKEN=xyz -w /work sbx_2f0c -- /bin/sh -c 'echo $TOKEN'
# xyz
```

| Argument | Description |
| --- | --- |
| `<ID>` | Sandbox to run in. |
| `<COMMAND> [ARGS...]` | Command to run, after `--`. Required. |

| Option | Description |
| --- | --- |
| `-e`, `--env <KEY=VALUE>` | Environment variable for the command. Repeatable. |
| `-w`, `--workdir <DIR>` | Directory to run in. Defaults to the image's `WORKDIR`, or the user's home when `--user` is given. |
| `-t`, `--pty` | Allocate a pty, so the command sees a terminal. Also spelled `--tty`. |
| `-u`, `--user <NAME>` | Guest user to run as. Defaults to root. Create one with [`user create`](#user-create). |

The image's own environment still applies. Your `--env` values win where the two
name the same variable, and `--workdir` wins over the image's `WORKDIR`. See
[TEMPLATES.md](TEMPLATES.md).

Standard input is forwarded when it is a pipe or a file:

```sh
cat main.py | burrow exec sbx_2f0c -- python3 -
```

## connect

Open an interactive shell in a sandbox. Aliased as `ssh` and `shell`. This is
`exec --pty` with a default command.

```
burrow connect [OPTIONS] <ID> [-- <COMMAND> [ARGS...]]
```

```sh
burrow connect sbx_2f0c
# / # ls /work
```

| Argument | Description |
| --- | --- |
| `<ID>` | Sandbox to connect to. |
| `<COMMAND> [ARGS...]` | Shell to start, after `--`. Defaults to `/bin/sh`. |

| Option | Description |
| --- | --- |
| `-u`, `--user <NAME>` | Guest user to open the shell as. Defaults to root. |

Your terminal goes raw for the session, and the guest's terminal follows its
size. It needs a terminal on standard input; to pipe a command in, use
[`exec`](#exec).

## logs

Replay a command's recent output and follow it until it exits. The command's
exit status becomes the CLI's.

```
burrow logs <ID> <COMMAND_ID>
```

```sh
burrow logs sbx_2f0c cmd_2
# epoch 1/10 loss 2.31
# epoch 2/10 loss 1.84
```

| Argument | Description |
| --- | --- |
| `<ID>` | Sandbox the command runs in. |
| `<COMMAND_ID>` | Command id, from [`top`](#top). |

The command id is required. A sandbox is a machine running any number of
commands, and its own console log is written on the node where no RPC reads it,
so there is no sandbox-wide stream to attach to:

```sh
burrow logs sbx_2f0c
# Error: burrow logs follows one command, so it needs a command id:
# `burrow logs sbx_2f0c <COMMAND-ID>`. `burrow top sbx_2f0c` lists them
```

The guest keeps the last 256 KiB of each command's output, so a chatty command
replays its tail rather than everything it has said. Attaching to a command that
has already finished replays what is left and prints nothing more. Any number of
terminals can follow the same command at once.

## kill

Signal a running command.

```
burrow kill [OPTIONS] <ID> <COMMAND_ID>
```

```sh
burrow kill sbx_2f0c cmd_2
# signalled cmd_2
burrow kill sbx_2f0c cmd_2 --signal 15
```

| Argument | Description |
| --- | --- |
| `<ID>` | Sandbox the command runs in. |
| `<COMMAND_ID>` | Command id, from [`top`](#top). |

| Option | Description |
| --- | --- |
| `--signal <N>` | Signal number. Defaults to 9 (SIGKILL). |

The command id is required here too. `docker kill` kills the container; burrow
kills one command, and guessing which one a bare sandbox id meant would either
signal the wrong process or destroy a sandbox nobody asked to lose:

```sh
burrow kill sbx_2f0c
# Error: burrow kill signals one command, so it needs a command id:
# `burrow kill sbx_2f0c <COMMAND-ID>`. `burrow top sbx_2f0c` lists them.
# To stop the sandbox use `burrow stop sbx_2f0c`, to destroy it `burrow rm sbx_2f0c`
```

Signalling a command that has already exited fails: its pid belongs to something
else by now.

## user

Create users inside the guest, so commands need not all run as root. See
[CONCEPTS.md](CONCEPTS.md#running-as-separate-users) for what that separation
does and does not protect.

### user create

```
burrow user create <ID> <NAME>
```

```sh
burrow user create sbx_2f0c alice
# alice uid=1000 gid=1000 home=/home/alice
burrow exec sbx_2f0c --user alice -- whoami
# alice
```

| Argument | Description |
| --- | --- |
| `<ID>` | Sandbox to create the user in. |
| `<NAME>` | User name: 1 to 32 characters matching `[a-z_][a-z0-9_-]*`. |

The home directory is created 0700, so no other user in the sandbox can read it.
Commands run with `--user` start there and get `HOME`, `USER` and `LOGNAME` to
match.

## group

Create groups and manage who is in them. A group is how two users share files on
purpose.

### group create

```
burrow group create <ID> <NAME>
```

```sh
burrow group create sbx_2f0c team
# team gid=1002 dir=/srv/team
```

| Argument | Description |
| --- | --- |
| `<ID>` | Sandbox to create the group in. |
| `<NAME>` | Group name, under the same rules as a user name. |

The shared directory is group-owned and setgid `2770`, so a file one member
creates in it stays readable by the rest of the group and invisible to everyone
else.

### group add

```
burrow group add <ID> <USER> <GROUP>
```

```sh
burrow group add sbx_2f0c alice team
# alice joined team
```

### group remove

```
burrow group remove <ID> <USER> <GROUP>
```

```sh
burrow group remove sbx_2f0c bob team
# bob left team
```

A user removed from a group loses access to its shared directory on their next
command.

## copy

Copy one file between this machine and a sandbox. Aliased as `cp`.

```
burrow copy <SRC> <DST>
```

```sh
burrow copy ./local.txt sbx_2f0c:/work/remote.txt
burrow copy sbx_2f0c:/work/out.json ./out.json
burrow copy sbx_2f0c:/work/out.json -
```

| Argument | Description |
| --- | --- |
| `<SRC>` | Source path. |
| `<DST>` | Destination path. |

Write a sandbox path as `<ID>:<PATH>`. Exactly one side has to be a sandbox
path: a local pair is a job for `cp`, and a sandbox pair is a transfer the API
does not offer. A destination of `-` writes the file to standard output. A
colon marks a sandbox path only when both sides of it are non-empty and what
precedes it contains no slash, so `./a:b`, `/tmp/a:b`, `:/work` and `sbx-1:`
are all local.

## dir

List a directory inside a sandbox.

```
burrow dir <ID> <PATH>
```

```sh
burrow dir sbx_2f0c /work
#         17  644  remote.txt
#          0  755  build/
```

| Argument | Description |
| --- | --- |
| `<ID>` | Sandbox to read. |
| `<PATH>` | Directory to list. |

## stop

Snapshot sandboxes to disk and stop their VMs. Aliased as `pause`. A stopped
sandbox keeps its disk, its memory image, and its address, and [`start`](#start)
brings it back where it left off.

```
burrow stop <ID> [ID...]
```

```sh
burrow stop sbx_2f0c sbx_91ab
# sbx_2f0c suspended
# sbx_91ab suspended
```

| Argument | Description |
| --- | --- |
| `<ID> [ID...]` | Sandboxes to stop. |

This is not `docker stop`. Nothing inside the guest is signalled and no process
exits: the VM's memory is written to disk and the machine is frozen, so a
process mid-write is still mid-write when you start it again.

Each id is attempted. A failure is reported and the rest still run, and the CLI
exits nonzero if any of them failed.

## start

Restore a stopped sandbox from its snapshot, and report how long it took.
Aliased as `resume`.

```
burrow start <ID>
```

```sh
burrow start sbx_2f0c
# sbx_2f0c running in 42ms
```

| Argument | Description |
| --- | --- |
| `<ID>` | Sandbox to start. |

## sessions

List the VMs a sandbox has run, newest first. A sandbox outlives its VMs: `stop`
ends one and `start` starts the next, and a fork or a create from a snapshot
starts one from state written elsewhere. See
[PERSISTENCE.md](PERSISTENCE.md#sessions).

```
burrow sessions <ID>
```

```sh
burrow sessions sbx_2f0c
# SESSION      START    END         STARTED AT            ENDED AT
# ses_8dff...  resume   open        2026-09-03T09:59:23Z  -
# ses_737f...  boot     suspended   2026-09-03T09:59:22Z  2026-09-03T09:59:23Z
```

| Argument | Description |
| --- | --- |
| `<ID>` | Sandbox whose sessions to list. |

`START` is `boot` from a template, `restore` from a fork or a snapshot, or
`resume` from the sandbox's own stop state. `END` is `open` for the VM running
now, `suspended`, `deleted`, `failed`, or `unknown` for a session that was open
when the node died. An `unknown` session has no end time, because nothing
recorded when its VM stopped.

Each node keeps the 64 most recent sessions of a sandbox and evicts the rest.
The list belongs to the sandbox and goes when you delete it.

## commit

Save a sandbox's state as a snapshot. The sandbox keeps running.

```
burrow commit [--expiration-secs <SECS>] <ID>
```

```sh
burrow commit build-env
# snap_c53d56f0c90c44979070dd02e95801df (38M) in 913ms
```

| Argument | Description |
| --- | --- |
| `<ID>` | Sandbox to snapshot, by id or name. |

| Option | Description |
| --- | --- |
| `--expiration-secs <SECS>` | Seconds from last use before the snapshot is swept. Falls back to the sandbox's `--snapshot-expiration-secs`, then to no expiry. |

Unlike `docker commit`, this captures the live machine and not just a filesystem
layer: memory, open files and running processes are all in the snapshot, so a
sandbox created from it comes up where the source was rather than booting.

`burrow snapshot create` is the same command under its older name, and
[`snapshot`](#snapshot) is where you list and delete what it writes.

## snapshot

Snapshots are state kept as an object you can start new sandboxes from. Unlike a
sandbox's own stop state, a snapshot outlives the sandbox it came from. See
[PERSISTENCE.md](PERSISTENCE.md#snapshots). Aliased as `snapshots`.

```
burrow snapshot create <ID> [--expiration-secs <SECS>]
burrow snapshot ls [<ID>]
burrow snapshot rm <SNAPSHOT> [SNAPSHOT...]
```

```sh
burrow snapshot ls build-env
# SNAPSHOT       SANDBOX       TEMPLATE  SIZE  CREATED               EXPIRES
# snap_c53d...   sbx_f31b...   alpine     38M  2026-09-03T09:21:20Z  never

burrow create --name from-snap --snapshot snap_c53d56f0c90c44979070dd02e95801df
burrow snapshot rm snap_c53d56f0c90c44979070dd02e95801df
```

| Command | Description |
| --- | --- |
| `snapshot create <ID>` | Save the sandbox's state. The sandbox keeps running. Same as [`commit`](#commit). |
| `snapshot ls [<ID>]` | List snapshots, newest first. Naming a sandbox lists only its own. |
| `snapshot rm <SNAPSHOT>...` | Delete snapshots, freeing their disk on the node holding them. |

A sandbox created with `--snapshot` restores rather than boots, and takes its
template and machine shape from the snapshot, so `--template`, `--vcpus` and
`--mem-mib` may not disagree with it. Snapshots are node-local, so the sandbox is
placed on the node holding the snapshot.

## fork

Create a sandbox from another's current state. The source keeps running, and its
state is written first, so the child starts from the state as of the call.

```
burrow fork [OPTIONS] <ID>
```

```sh
burrow fork sbx_2f0c
# sbx_91ab0f5c0c1e4a7c9a0b1c2d3e4f5a6b in 61ms
```

| Argument | Description |
| --- | --- |
| `<ID>` | Sandbox to fork. |

| Option | Description |
| --- | --- |
| `--id <ID>` | Id for the child. Omitted has one generated. |
| `--name <NAME>` | Name for the child. A fork never inherits its source's name. |
| `--node-label <KEY=VALUE>` | Require the source's node to carry this label. Repeatable. |
| network options | The [`create`](#create) network group, applied to the child. |
| access options | The [`create`](#create) `--no-exec`, `--no-upload`, `--no-download`, `--fs-scope` and `--max-upload-bytes` options, applied to the child. |

Each policy section is inherited on its own, so a child given only access options
keeps the source's egress policy and the other way round. The child's machine
configuration always comes from the snapshot.

`--node-label` cannot move the child, since a fork is built where its source's
state already is. It is a precondition: a source on a node without those labels
is refused rather than the constraint being dropped.

## remove

Destroy sandboxes and everything they hold, including their snapshots. Aliased
as `rm`.

```
burrow remove <ID> [ID...]
```

```sh
burrow remove sbx_2f0c sbx_91ab
# deleted sbx_2f0c
# deleted sbx_91ab
```

| Argument | Description |
| --- | --- |
| `<ID> [ID...]` | Sandboxes to destroy. |

Each id is attempted. A failure is reported and the rest still run, and the CLI
exits nonzero if any of them failed.

Removing a sandbox whose node has missed its heartbeats works too. The
orchestrator cannot tell the node, so it drops the sandbox on its own word: the
name and the capacity come back at once, and if that node ever returns still
holding the sandbox, it is destroyed there rather than reappearing here.

## config

Read and replace a sandbox's configuration. Each subcommand replaces a whole set
rather than patching it, so removing something is one call.

```
burrow config <SUBCOMMAND> <ID> [OPTIONS]
```

| Subcommand | Does |
| --- | --- |
| `list` | Print the sandbox's current configuration and usage |
| `lifetime` | Move the clocks the sandbox is measured against |
| `network-policy` | Replace the egress policy |
| `access` | Replace the exec and file policies |
| `tags` | Replace the tag set |
| `ports` | Replace the published ports |

### config list

Print one sandbox's record. Same output as [`inspect`](#inspect), and the same
`--json`.

```
burrow config list [--json] <ID>
```

```sh
burrow config list sbx_2f0c
# sandbox         sbx_2f0c
# state           running
# node            node_a
# template        default
# created         2026-09-02T07:57:51Z
# address         10.99.0.10
# cpu             5550ms
# network         557.9 KiB in / 557.8 KiB out
# vcpus           1 (default)
# mem-mib         512 (default)
# net             allowlist
# allow-domain    pypi.org
# tags            env=staging
```

| Option | Description |
| --- | --- |
| `--json` | Emit the record as JSON instead of the readable field list. |

### config lifetime

Move the clocks a running sandbox is measured against. The reaper reads them on
its next pass, so an extension takes effect without restarting anything.

```
burrow config lifetime <ID> <SECS> [OPTIONS]
```

```sh
burrow config lifetime sbx_2f0c 7200 --idle-suspend-secs 900
# sbx_2f0c max-lifetime 7200s
```

| Argument | Description |
| --- | --- |
| `<ID>` | Sandbox to update. |
| `<SECS>` | New `--max-lifetime-secs`, measured from when the sandbox was created. `0` lets it live until something deletes it. |

| Option | Description |
| --- | --- |
| `--idle-suspend-secs <SECS>` | Also replace the idle-suspend timeout. |
| `--suspended-ttl-secs <SECS>` | Also replace how long a suspended sandbox is kept. |

The lifetime is a total measured from creation, not an amount added to what is
left, so `7200` means the sandbox lives two hours from when you created it. A
value already in the past destroys it on the next pass.

The machine shape is not movable. A running VM's configuration is fixed and a
restore takes it from the snapshot, so `vcpus`, memory, and scratch disk are
refused rather than quietly ignored. To change those, create a new sandbox, or
take a snapshot and create from it at the shape you want.

### config network-policy

Replace a running sandbox's egress policy. Firewall rules, proxy allowlist, DNS
filtering, and header injection all re-render at once.

```
burrow config network-policy <ID> [NETWORK OPTIONS]
```

```sh
burrow config network-policy sbx_2f0c --net allowlist --allow-domain pypi.org
# sbx_2f0c network policy updated
```

| Argument | Description |
| --- | --- |
| `<ID>` | Sandbox to update. |

Takes the same network options as [`create`](#create). The policy is replaced
whole, so an option you leave out is an allowance withdrawn, and `--net none`
locks the sandbox down. TLS inspection can only be turned on at creation, because
the guest is given the inspection CA when it starts.

### config access

Replace a running sandbox's exec and file policies. Both are enforced by the
node before a command or a path reaches the guest, so the change is in force on
the next call and nothing in the sandbox is disturbed.

```
burrow config access <ID> [OPTIONS]
```

```sh
burrow config access sbx_2f0c --no-exec
# sbx_2f0c exec denied · upload allowed · download allowed
```

| Argument | Description |
| --- | --- |
| `<ID>` | Sandbox to update. |

| Option | Description |
| --- | --- |
| `--no-exec` / `--allow-exec` | Refuse or allow `exec`, `run` and `connect`. |
| `--no-upload` / `--allow-upload` | Refuse or allow uploads. |
| `--no-download` / `--allow-download` | Refuse or allow downloads. |
| `--fs-scope <PATH>` | Absolute path file operations are confined to. Repeatable, at most 16. |
| `--max-upload-bytes <N>` | Cap on a single upload. `0` is unlimited. |

Naming an allowance both ways is refused by the parser rather than resolved by
argument order, so `--no-exec --allow-exec` is an error.

There are two sections here, exec and files, and what you leave unmentioned
matters:

- A section you say something about is replaced wholesale. Naming any one file
  option settles all four, so restate the parts you want kept: `--no-upload` on
  its own also reopens the scopes and clears the upload cap.
- A section you say nothing about is left exactly as it is. It does not become
  "allow everything".

So `--no-upload --fs-scope /work` tightens files and leaves exec wherever it was,
and `--no-exec` denies exec without touching a single file rule. This differs on
purpose from [`create`](#create), where an option you never name means the
sandbox is unrestricted: on a live sandbox that reading would let someone
tightening files silently re-open exec.

Naming nothing at all is an error rather than a no-op. Path scopes are checked
the same way `create` checks them: absolute, no `..`, at most 16.

### config tags

Replace a sandbox's tag set.

```
burrow config tags <ID> [--tag <KEY=VALUE>...]
```

```sh
burrow config tags sbx_2f0c --tag env=production --tag owner=platform
# sbx_2f0c now has 2 tags
```

| Argument | Description |
| --- | --- |
| `<ID>` | Sandbox to update. |

| Option | Description |
| --- | --- |
| `--tag <KEY=VALUE>` | Tag to keep. Repeatable. Passing none clears the set. |

### config ports

Replace a sandbox's published ports. Ports you leave out are closed, and ports
already published stay on the host port they have.

```
burrow config ports <ID> [-p <PORT>...]
```

```sh
burrow config ports sbx_2f0c -p 8080 -p 9000
# node:20000 -> guest :8080
# node:20001 -> guest :9000
```

| Argument | Description |
| --- | --- |
| `<ID>` | Sandbox to update. |

| Option | Description |
| --- | --- |
| `-p`, `--port <PORT>` | Guest port to publish. Repeatable. Passing none closes them all. |

## expose

Publish one guest port on the node's address.

```
burrow expose [--host-port <PORT>] <ID> <GUEST_PORT>
```

```sh
burrow expose sbx_2f0c 8000
# http://8000-sbx_2f0c.node-a.sandbox.example.com/ -> guest :8000 (node-a:20002)
```

| Argument | Description |
| --- | --- |
| `<ID>` | Sandbox to publish from. |
| `<GUEST_PORT>` | Port inside the sandbox. |

| Option | Description |
| --- | --- |
| `--host-port <PORT>` | Preferred host port. Omitted lets the node pick. |

When the node holding the sandbox runs an edge router, the port also answers on
`http://<guest-port>-<sandbox-id>.<edge-domain>/`, shown first with the node
address beside it in brackets. The node address is where the port actually is;
the URL is the name that node's own edge answers for, and traffic arriving on it
for a stopped sandbox wakes it.

The edge lives on the node, and it is the only one: a node with none has no
hostname routing at all, and you get the node address alone. The port still
works; it just has no name. See [EDGE.md](EDGE.md) for what to run on a
node to give it one.

A published port cannot wake a suspended sandbox, and it holds a port on the
node open to anyone who can reach it. For a non-HTTP service, prefer
[`share`](#share) unless the far end has to connect with an ordinary client and
no burrow-specific software.

To publish at creation instead, use [`create -p`](#create).

## port

List a sandbox's published ports. Aliased as `ports`.

```
burrow port <ID>
```

```sh
burrow port sbx_2f0c
# http://8000-sbx_2f0c.node-a.sandbox.example.com/ -> guest :8000 (node-a:20002)
```

| Argument | Description |
| --- | --- |
| `<ID>` | Sandbox to read. |

A sandbox with nothing published prints `no published ports`.

## unexpose

Withdraw one published port, by its host port.

```
burrow unexpose <ID> <HOST_PORT>
```

```sh
burrow unexpose sbx_2f0c 20002
# closed 20002
```

| Argument | Description |
| --- | --- |
| `<ID>` | Sandbox to update. |
| `<HOST_PORT>` | Host port to close, as [`port`](#port) reports it. |

## share

Share a sandbox through a tailcat address: a WireGuard tunnel bootstrapped over
a DERP relay that any `tailcat` client can dial, with no host port and no edge.

```
burrow share [--port <PORT>]... [--udp-port <PORT|all>]... [--allow <NODEKEY>]... [--rotate] [--no-transparent-ip] [--show] <ID>
```

```sh
burrow share sbx_2f0c --port 22
# tcXXXXXXXXXXXXXXXXXXXX
tailcat ssh tcXXXXXXXXXXXXXXXXXXXX
```

| Argument | Description |
| --- | --- |
| `<ID>` | Sandbox to share. |

| Option | Description |
| --- | --- |
| `--port <PORT>` | Guest TCP port reachable through the share. Repeatable, or comma-separated. Omitted shares every port. |
| `--udp-port <PORT>` | Guest UDP port reachable through the share, or `all`. Repeatable. Omitted shares no UDP. |
| `--allow <NODEKEY>` | Client node key admitted, as `nodekey:<hex>`. Repeatable. Omitted admits anyone holding the address. |
| `--rotate` | Issue new keys, and so a new address, to an existing share. The old address stops working. |
| `--no-transparent-ip` | Source connections from the sandbox gateway. By default the guest sees the client's own last verified public IPv4 on the packet. |
| `--show` | Print the existing share without changing it. |

The address alone goes to stdout; what the share admits goes to stderr. Running
`share` again on a shared sandbox reshapes it and keeps the address. The
address is the credential: anyone holding it can connect, so treat it as a
secret. A connection through a share wakes a suspended sandbox. See
[SHARE.md](SHARE.md).

## unshare

Revoke a sandbox's share. Its address stops working at once.

```
burrow unshare <ID>
```

```sh
burrow unshare sbx_2f0c
# share revoked
```

## images

List templates, with their size and whether a warm snapshot is ready. Same as
[`templates ls`](#templates-ls).

```
burrow images
```

```sh
burrow images
# TEMPLATE                       SIZE  WARM
# default                         64M  yes
# python                         398M  no
```

A template is the rootfs a sandbox boots, held on the nodes. There is no local
image cache to list, so this always reports what the fleet has. See
[TEMPLATES.md](TEMPLATES.md).

## pull

Import an OCI image as a template. Build progress streams as it runs. Same as
[`templates import`](#templates-import).

```
burrow pull [--name <NAME>] <IMAGE>
```

```sh
burrow pull python:3.12-slim
# imported python:3.12-slim as template python-3.12-slim (398MiB)

burrow create --template python-3.12-slim
```

| Argument | Description |
| --- | --- |
| `<IMAGE>` | Image reference: `[registry/]repository[:tag\|@digest]`. No tag means `:latest`. |

| Option | Description |
| --- | --- |
| `--name <NAME>` | Template name. Defaults to the repository plus the tag, so `ghcr.io/org/tool:v1` becomes `tool-v1` and `alpine:latest` becomes `alpine`. A digest reference keeps the bare repository name. See [TEMPLATES.md](TEMPLATES.md#how-an-import-is-named). |

This is a conversion, not a download into a cache. The image's layers are
flattened into a rootfs on a node and kept as a template, and its `ENV`,
`WORKDIR` and `ENTRYPOINT` come with it. Pull once, then create as many
sandboxes from the template as you want.

## templates

Manage the guest images sandboxes boot from. See [TEMPLATES.md](TEMPLATES.md).

```
burrow templates <SUBCOMMAND>
```

### templates ls

List templates, with their size and whether a warm snapshot is ready. Same as
[`images`](#images).

```
burrow templates ls
```

```sh
burrow templates ls
# TEMPLATE                       SIZE  WARM
# default                         64M  yes
# python                         398M  no
```

### templates import

Import an OCI image as a template. Same as [`pull`](#pull).

```
burrow templates import [--name <NAME>] <IMAGE>
```

```sh
burrow templates import python:3.12-slim
# imported python:3.12-slim as template python-3.12-slim (398MiB)
```

| Argument | Description |
| --- | --- |
| `<IMAGE>` | Image reference: `[registry/]repository[:tag\|@digest]`. No tag means `:latest`. |

| Option | Description |
| --- | --- |
| `--name <NAME>` | Template name. Defaults to the repository plus the tag, as [`pull`](#pull) does. |

### templates rm

Remove a template. Sandboxes already running from it are unaffected.

```
burrow templates rm <NAME>
```

```sh
burrow templates rm python
# removed python
```

| Argument | Description |
| --- | --- |
| `<NAME>` | Template to remove. |

## audit

Show recorded egress attempts and DNS lookups, newest first. Every attempt is
recorded, allowed or not. See [FIREWALL.md](FIREWALL.md).

```
burrow audit [OPTIONS]
```

```sh
burrow audit --denied --limit 20
# AT                    SANDBOX   ALLOWED HOST          REASON
# 2026-09-02T05:35:09Z  sbx_2f0c  no      example.com   request host is not in the allowlist
```

| Option | Description |
| --- | --- |
| `--sandbox <ID>` | Restrict to one sandbox. |
| `--denied` | Only attempts the proxy refused. |
| `--since <RFC3339>` | Lower bound, for example `2026-08-27T00:00:00Z`. |
| `--limit <N>` | Rows to return. Defaults to 50. |

## nodes

Inspect the nodes sandboxes are placed on.

```
burrow nodes <SUBCOMMAND>
```

### nodes ls

List registered nodes, with capacity and health.

```
burrow nodes ls
```

```sh
burrow nodes ls
# NODE     ADDRESS     CPUS  MEM_MIB  FREE_MIB  SBX  STATE  LABELS                  HOSTNAME
# node_a   node:7071      4     7922      7375    1  ready  rack=a1,tier=general    4f09e04420c7
# node_b   node2:7071     4     7922      7139    4  ready  rack=b7,tier=dedicated  b427c731a9e9
```

A node the orchestrator has not heard from recently shows as `stale`, and one you
have drained shows as `draining`.

`LABELS` is what the operator started that node with, as
`burrowd serve --label rack=b7` or `BURROW_NODE_LABELS=rack=b7,tier=dedicated`.
Constrain a create to them with [`create --node-label`](#create).

### nodes drain

Stop placing new sandboxes on a node.

```
burrow nodes drain [--suspend] <NODE_ID>
```

```sh
burrow nodes drain --suspend node_a
# draining node_a (3 suspended)
```

| Argument | Description |
| --- | --- |
| `<NODE_ID>` | Node to drain. |

| Option | Description |
| --- | --- |
| `--suspend` | Also snapshot the sandboxes the node is running. |

### nodes undrain

Start placing sandboxes on a node again.

```
burrow nodes undrain <NODE_ID>
```

```sh
burrow nodes undrain node_a
# node_a accepting sandboxes again
```

| Argument | Description |
| --- | --- |
| `<NODE_ID>` | Node to accept sandboxes again. |
