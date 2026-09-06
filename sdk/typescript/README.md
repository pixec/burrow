# @pixec/burrow

Run untrusted code in Firecracker microVMs from Node.

```sh
npm install @pixec/burrow
```

The SDK talks gRPC to a [burrow](../../) orchestrator. It needs Node 18 or newer
and depends only on `@grpc/grpc-js` and `@grpc/proto-loader`.

## Quickstart

Create a sandbox, run a command, and destroy it.

```ts
import { Sandbox } from "@pixec/burrow";

const sandbox = await Sandbox.create({ template: "python" });

const result = await sandbox.runCommand("echo", ["hello"]);
console.log(result.exitCode, result.stdout()); // 0 "hello\n"

await sandbox.delete();
```

Use `await using` and the sandbox destroys itself when the scope exits, even if
your code throws.

```ts
await using sandbox = await Sandbox.create({ template: "python" });
await sandbox.runCommand("echo", ["hello"]);
```

Every `Sandbox.create` and `Sandbox.get` opens its own gRPC channel. `delete()`
and `await using` release it; if you want to keep the sandbox and drop the
connection, call `sandbox.close()`. To share one channel across many sandboxes,
use [`Burrow`](#manage-many-sandboxes).

## Create a sandbox

`Sandbox.create` boots a VM and returns once it accepts commands. Everything is
optional.

```ts
const sandbox = await Sandbox.create({
  template: "python-tools",
  tags: { owner: "ci", run: "482" },
  resources: {
    vcpus: 2,
    memoryMib: 2048,
    diskMib: 4096,
    maxLifetimeSecs: 3600,
    idleSuspendSecs: 300,
    suspendedTtlSecs: 86400,
  },
  network: {
    mode: "allowlist",
    allowDomains: ["pypi.org", "*.pythonhosted.org"],
  },
});
```

### Options

| Option | Default | What it does |
|---|---|---|
| `name` | none | Name for the sandbox, the only identity you choose. Ids are generated |
| `template` | none | Guest image to boot, as imported by `burrow pull`. Required unless `snapshot` is given. Also spelled `image` |
| `snapshot` | none | Restore from a snapshot instead of booting a template |
| `tags` | `{}` | Up to 16 key/value pairs, used for filtering later. Also spelled `metadata` |
| `nodeLabels` | `{}` | Labels the hosting node must carry, all of them. See [Choose where a sandbox runs](#choose-where-a-sandbox-runs) |
| `resources` | 1 vCPU, 512 MiB | Machine shape, lifetime, and snapshot retention |
| `network` | `"none"` | Egress policy, as a mode, a shorthand, or a full policy object. Also spelled `networkPolicy` |
| `env` | `{}` | Environment merged under every command this handle runs |
| `networks` | `[]` | Private networks to join |
| `alias` | sandbox id | Name this sandbox answers to on those networks |
| `exec` | everything allowed | Whether callers may run commands in the sandbox |
| `fs` | everything allowed | What callers may do to the sandbox's filesystem |
| `autoResume` | `true` | Resume and retry once when a call finds the sandbox stopped |
| `timeoutMs` | `120000` | How long to wait for the boot |
| `signal` | none | `AbortSignal` that cancels the call |

`vcpus`, `memoryMib`, `allowDomains` and `allowCidrs` are also accepted at the
top level, where they fill in the matching `resources` or `network` field.

### Resources

| Field | Default | What it does |
|---|---|---|
| `vcpus` | `1` | vCPUs given to the guest |
| `memoryMib` | `512` | Guest memory |
| `diskMib` | node default | Writable scratch disk |
| `maxLifetimeSecs` | `0` | Hard cap on the sandbox's life. `0` is unlimited |
| `idleSuspendSecs` | `0` | Suspend after this long with no activity. `0` never suspends |
| `suspendedTtlSecs` | `0` | Delete a sandbox suspended this long, releasing its disk and address. `0` keeps it forever |
| `snapshotExpirationSecs` | `0` | Sweep a snapshot this long after it was last used. `0` keeps it indefinitely |
| `keepLastSnapshots` | `0` | Keep only this many snapshots of the sandbox. `0` is unlimited, otherwise 1 to 10 |

`idleSuspendSecs` and `suspendedTtlSecs` compose. Idle parks a sandbox, and the
TTL decides how long the parked state is worth paying for.

The SDK sends zeroes rather than its own defaults, so the numbers above are what
the node fills in.

### Exec and file access

Both sections are enforced on the node, before anything reaches the guest.
Leaving one out allows everything it covers, so a sandbox created without them
behaves exactly as it always has.

| `exec` field | Default | What it does |
|---|---|---|
| `allowExec` | `true` | `false` refuses every exec, terminal and `runCode` on this sandbox |

| `fs` field | Default | What it does |
|---|---|---|
| `allowUpload` | `true` | `false` refuses uploads |
| `allowDownload` | `true` | `false` refuses downloads |
| `pathScopes` | `[]` | Absolute paths uploads, downloads, listings and watches are confined to. At most 16; empty is the whole filesystem |
| `maxUploadBytes` | `0` | Ceiling on a single upload. `0` is unlimited |

```ts
const sandbox = await Sandbox.create({
  exec: { allowExec: false },
  fs: { pathScopes: ["/work"], maxUploadBytes: 8 * 1024 * 1024 },
});
```

Scopes are matched on whole path components, so `/data` admits `/data/in.csv`
and refuses `/database/dump.sql`. A path carrying `..` is refused outright.
Both sections can be tightened later, with different rules about what an omitted
section means: see [Exec and file policy](#exec-and-file-policy).

## Get, get-or-create, and list

Reattach to a sandbox you created earlier.

```ts
const sandbox = await Sandbox.get({ id: "sbx_..." });
```

Sandboxes can carry a name, and every method that takes an identifier takes a
name just as happily as an id. The server resolves an id first and a name
second, and the two cannot collide.

```ts
const api = await Sandbox.create({ name: "api" });
const same = await Sandbox.get({ name: "api" });
```

A name is 1 to 63 characters of lowercase letters, digits and `-`, not starting
or ending with `-`. It is unique across the fleet, so a second create under a
name in use fails with `already_exists`, and it is fixed once the sandbox
exists. Nothing generates one: a sandbox created without a name has none, and
`sandbox.name` falls back to its id.

`getOrCreate` takes a name and gives you the sandbox behind it, creating it the
first time. Every worker can run the same call: the losers of a race retry the
lookup with a backoff, up to ten attempts, and get the winner's sandbox rather
than making one of their own. If it still has not appeared by then, the call
fails with `unavailable`.

```ts
const sandbox = await Sandbox.getOrCreate({
  name: "build-482",
  template: "python-tools",
  onCreate: (s) => s.writeFiles([{ path: "/work/app.py", content: source }]),
  onResume: (s) => console.log("resumed", s.name),
});
```

| Option | What it does |
|---|---|
| `name` | The name to get or create. Required: ids are generated, so there is none to ask for |
| `onCreate` | Awaited when this call is the one that created the sandbox |
| `onResume` | Called whenever this handle resumes the sandbox, auto-resume included |
| `resume` | Resume a stopped sandbox up front. Defaults to false |
| create options | Everything `create` takes, applied only when the sandbox has to be made |

Create options are ignored when the sandbox already exists. It is handed back as
it is rather than reconfigured to match, so `getOrCreate` never reshapes
somebody else's work.

Ids are always generated by the server. A name is the identity you choose, and
it costs nothing: a pooled spare can be named on its way out of the warm pool,
so a named create is served just as fast as an unnamed one.

List sandboxes, optionally filtered by one tag. The filter is a single
`"key=value"` pair, matched exactly.

```ts
for await (const sandbox of Sandbox.list({ tag: "owner=ci" })) {
  console.log(sandbox.id, sandbox.state, sandbox.tags);
}

const all = await Sandbox.list().toArray();
```

Every handle from one `list` shares a channel, released when the iteration
finishes.

## Run commands

`runCommand` runs a command to completion and returns its result. Pass the
program and its arguments separately and the command goes straight to execve,
with no shell involved.

```ts
const install = await sandbox.runCommand("pip", ["install", "cowsay"]);

install.exitCode; // 0
install.success;  // true
install.stdout(); // the whole stream, as text
install.stderr();
```

Pass a bare string and it runs through `/bin/sh -c`, so pipes and redirection
work.

```ts
await sandbox.runCommand("cat /etc/hostname | tr a-z A-Z");
```

A non-zero exit is returned rather than thrown. Set `check: true` to invert
that.

```ts
try {
  await sandbox.runCommand("exit 1", [], { check: true });
} catch (err) {
  err.exitCode; // 1
}
```

`runCommand` also takes a single object, which is where `cwd`, `env`, and
output streams live.

```ts
const build = await sandbox.runCommand({
  cmd: "make",
  args: ["-j4"],
  cwd: "/work",
  env: { CFLAGS: "-O2" },
  stdout: process.stdout,
  stderr: process.stderr,
});
```

| Field | What it does |
|---|---|
| `cmd` | Program, or a whole shell line when `args` is omitted |
| `args` | Arguments, passed to execve with no shell |
| `shell` | Force the shell path. Defaults to on when `args` is empty |
| `cwd` | Directory to run in. Defaults to the image's `WorkingDir` |
| `env` | Environment for this command. Wins over the handle's `env` defaults |
| `stdout`, `stderr` | Node `Writable`s that receive output as it arrives |
| `onStdout`, `onStderr` | The same output as callbacks |
| `check` | Throw `CommandFailedError` on a non-zero exit |
| `detached` | Return a handle immediately instead of waiting |
| `pty` | Allocate a pty, with `rows` and `cols` |
| `user` | Guest user to run as. Defaults to root |
| `timeoutMs` | Deadline for this command |
| `autoResume` | Override the handle's auto-resume for this call |
| `signal` | `AbortSignal` that cancels the command |

Two sharp edges. `check` is only honoured on the blocking path, so
`{ detached: true, check: true }` ignores it and you inspect the exit code
yourself. And `shell: true` together with `args` joins them with spaces and
quotes nothing, so build the line yourself if any argument can contain a space.

Commands run as root unless `user` names someone else. See
[Users and groups](#users-and-groups).

### Environment defaults

`env` on `create` or `getOrCreate` is merged under every command that handle
runs, and a per-command `env` wins over it. `asUser` and `fork` carry it along;
`terminal()` does not, so pass a terminal's environment to the terminal.

```ts
const sandbox = await Sandbox.create({ env: { NODE_ENV: "test" } });
await sandbox.runCommand("printenv NODE_ENV"); // test
```

This lives in the client, not in the sandbox. A handle from `Sandbox.get` in
another process does not have it, and nothing in the guest can read it back.
Bake anything that has to survive into the template.

### Stream output

Pass `detached: true` to get a handle back immediately. Read `logs()` as the
command runs, or `wait()` for the finished result. Use one or the other: both
drain the same stream, and the second call throws `failed_precondition` saying
the output has already been consumed. `kill()` signals the command, SIGKILL by
default; `killed()` is the same call, awaited. See
[Signalling a command](#signalling-a-command).

```ts
const job = await sandbox.runCommand({
  cmd: "npm",
  args: ["install"],
  detached: true,
});

for await (const chunk of job.logs()) {
  if (chunk.type === "stdout") process.stdout.write(chunk.data);
  if (chunk.type === "exit") console.log("exit", chunk.exitCode);
}
```

`job.cmdId` is the command's id in the sandbox, not a local name. Keep it and
another process can pick the same command up again. See
[Reattach to a command](#reattach-to-a-command).

Callbacks work too, and so does a plain async iterator.

```ts
await sandbox.exec("make", {
  onStdout: (chunk) => process.stdout.write(chunk),
  onStderr: (chunk) => process.stderr.write(chunk),
});

for await (const chunk of sandbox.execStream("make")) {
  if (chunk.type === "stdout") process.stdout.write(chunk.data);
}
```

Pass `pty: true` for programs that behave differently on a terminal, such as
anything with colour, progress bars, or a REPL.

### Interactive terminals

`runCommand` runs to completion. When input arrives over time, from a browser
terminal or an agent driving a REPL, open a terminal instead. It keeps stdin
open and allocates a pty.

```ts
const term = sandbox.terminal({ cols: 120, rows: 40 });

term.onData((chunk) => process.stdout.write(chunk));
term.write("ls -la\n");
term.resize(50, 160);
term.signal(2); // SIGINT

await term.wait(); // resolves with the exit code
```

Bridging one to a WebSocket is the whole of a browser terminal backend.

```ts
wss.on("connection", async (ws) => {
  const sandbox = await Sandbox.create({ template: "python" });
  const term = sandbox.terminal({ cols: 80, rows: 24 });

  term.onData((chunk) => ws.send(chunk));
  term.onExit(() => ws.close());
  ws.on("message", (data) => term.write(data.toString()));
  ws.on("close", async () => {
    term.kill();
    await sandbox.delete();
  });
});
```

### Reattach to a command

A command belongs to the sandbox, not to the client that started it. Keep its
`cmdId` and you can come back to it from another process, another machine, or
after a crash.

```ts
const job = await sandbox.runCommand({ cmd: "./train.sh", detached: true });
await queue.put({ sandbox: sandbox.id, cmdId: job.cmdId });
```

```ts
// Somewhere else entirely.
const sandbox = await Sandbox.get({ id: sandboxId });
const job = await sandbox.getCommand(cmdId);

job.info.state;    // "running" or "exited"
job.info.exitCode; // meaningful once it has exited
job.info.user;     // who it runs as, empty for root

for await (const chunk of job.logs()) process.stdout.write(chunk.data);
```

`logs()` replays the output the guest still holds and then follows the command
live until it exits. Attaching to a command that has already finished replays
what is left and ends with its exit status, so the same code covers both. A
reattached handle differs from a detached one here: each `logs()` and `wait()`
opens its own attachment with no deadline, so any number of readers can attach
at once and each gets its own stream.

`wait()` drains an attachment and returns the finished result.

#### Signalling a command

`kill(signal)` signals the command and does not wait; it defaults to SIGKILL.
`killed(signal)` is the same call as a promise.

```ts
job.kill(15);
const result = await job.wait();
```

`kill()` swallows the failure it was asking for, the command having already
exited, and leaves everything else to reject. With nothing awaiting it that
surfaces as an unhandled rejection rather than as silence. The test is a
heuristic and not an exact one: any `failed_precondition` whose message does not
mention suspension is treated as "already exited". Await `killed()` to handle
these yourself:

```ts
try {
  await job.killed(15);
} catch (err) {
  if (err.code === "permission_denied") console.warn("exec is disabled on this sandbox");
}
```

What can fail: `permission_denied` when the sandbox's exec policy forbids
commands, since signals go through the same door as exec and a sandbox
tightened with `update({ exec: { allowExec: false } })` refuses them too;
`failed_precondition` when the sandbox is suspended, or when the command had
already exited; `not_found` for a command the guest has since evicted; and
transport failures when the node cannot be reached.

`listCommands()` returns everything the sandbox has run, oldest first.

```ts
for (const command of await sandbox.listCommands()) {
  console.log(command.cmdId, command.state, command.user, command.cmd.join(" "));
}
```

Two bounds are worth knowing. The guest keeps the last 256 KiB of each
command's output, oldest dropped, so a chatty command replays its tail rather
than everything it said. And it retains the 64 most recent finished commands;
past that the oldest is evicted, and `getCommand` on it fails with
`not_found`. A running command is never evicted.

## Users and groups

Every command runs as root by default. Give each agent its own user and they
stop sharing a home directory, an `~/.ssh`, and each other's temporary files.

```ts
const alice = await sandbox.createUser("alice");

alice.username; // "alice"
alice.uid;      // 1000
alice.home;     // "/home/alice", mode 0700

await sandbox.runCommand({ cmd: "whoami", user: "alice" });
```

A name is POSIX portable: `[a-z_][a-z0-9_-]*`, at most 32 characters. The home
is private, so one user cannot read another's files.

Groups are how two users share something on purpose. A group comes with a
directory both members can write, group-owned and setgid, so a file created
inside it stays readable by the rest of the group.

```ts
const team = await sandbox.createGroup("team");
await sandbox.addUserToGroup("alice", "team");
await sandbox.addUserToGroup("bob", "team");

team.sharedDir; // "/srv/team"

await sandbox.runCommand({ cmd: `echo hi > ${team.sharedDir}/note`, user: "alice" });
await sandbox.runCommand({ cmd: `cat ${team.sharedDir}/note`, user: "bob" });

await sandbox.removeUserFromGroup("bob", "team");
```

`asUser` returns a handle onto the same sandbox whose commands all run as one
user, which saves passing `user` to every call.

```ts
const alice = sandbox.asUser("alice");

await alice.runCommand("touch notes.txt"); // in /home/alice
await alice.mkDir("/home/alice/work");
await alice.writeFile("/home/alice/app.py", src);

const term = alice.terminal(); // a shell as alice
```

Commands, terminals, `mkDir` and `writeFile` run as the user. `writeFile` is
the guest agent's upload followed by a `chown` exec, so it costs a second call
and needs exec to be allowed. Reads do not work this way at all: `readFile`,
`listDir` and `downloadFile` are served by the agent, which is root, so a user
handle can still read a file its user could not.

This is a boundary inside one sandbox, not a replacement for one. The users
share a kernel and a VM, and root in the guest still reaches everything. Two
workloads that must not touch each other belong in two sandboxes.

## Work with files

Write several files with one call. Parent directories are created for you.

```ts
await sandbox.writeFiles([
  { path: "/work/app.py", content: "print('hi')\n" },
  { path: "/work/run.sh", content: "python3 /work/app.py\n", mode: 0o755 },
  { path: "/work/data.bin", content: new Uint8Array([1, 2, 3]) },
]);
```

Contents are text or bytes, and `mode` sets the unix mode on a created file.
Each file is its own upload, sent in order, so a failure part way through leaves
the earlier ones written.

Read a file back as text, as a stream, or as a `Buffer`.

```ts
const text = await sandbox.readFile("/work/app.py");        // string
const stream = await sandbox.readFile({ path: "/work/app.py" }); // Readable | null
const buffer = await sandbox.readFileToBuffer({ path: "/work/data.bin" }); // Buffer | null
```

The object forms return `null` when the file does not exist. The string form
throws a `not_found` error instead.

Copy a file out to the local filesystem with `downloadFile`. It returns the
absolute path it wrote, or `null` when the sandbox has no such file, and creates
the destination's parent directories unless you pass
`mkdirRecursive: false`.

```ts
const path = await sandbox.downloadFile("/work/report.pdf", "./out/report.pdf");
```

List directories and create them.

```ts
for (const entry of await sandbox.listDir("/work")) {
  console.log(entry.name, entry.isDir ? "dir" : entry.size);
}

await sandbox.mkDir("/work/src/components");
```

`sandbox.fs` groups the common ones for SDKs that namespace them, with
`listDir` spelled `readDir` there: `readFile`, `readFileToBuffer`, `writeFile`,
`writeFiles`, `readDir`, `mkDir`. Messages are capped at 64 MiB in both
directions, which is the ceiling on a single file transfer.

### Watch for changes

```ts
const watcher = await sandbox.watch("/work/src", {
  recursive: true,
  onEvent: (event) => console.log(event.type, event.path),
});

for await (const event of watcher) {
  if (event.type === "modified") rebuild(event.path);
}

watcher.stop();
```

Events are `created`, `modified`, and `deleted`. The guest polls and reports
differences every 500ms by default, which you change with `intervalMs`, floored
at 50ms. A change is seen within about one interval, and a file created and
deleted between two scans is not seen at all.

## Control the network

Sandboxes have no network by default. Access is opt-in.

```ts
await Sandbox.create({ template: "python" });  // no egress at all
await Sandbox.create({ network: "open" });    // unrestricted
await Sandbox.create({
  network: "allowlist",
  allowDomains: ["api.github.com", "*.githubusercontent.com"],
});
```

A leading `*.` is the only wildcard, and it does not cover the apex:
`*.example.com` matches `www.example.com` and `a.b.example.com` but not
`example.com`.

### Shorthands

The shorthand shapes other sandbox SDKs use are accepted everywhere a policy is,
which is `create`, `fork`, `update`, and `updateNetworkPolicy`.

```ts
await Sandbox.create({ networkPolicy: "allow-all" }); // mode "open"
await Sandbox.create({ networkPolicy: "deny-all" }); // mode "none"

await Sandbox.create({
  networkPolicy: {
    allow: ["api.github.com", "*.githubusercontent.com"],
    subnets: { allow: ["10.0.0.0/8"], deny: ["169.254.0.0/16"] },
  },
});
```

`allow` as an object carries per-domain rules. A `transform` sets headers on the
inspected requests the rule selects, which is header injection: the value stays
on the node, and reading the policy back gives you `<redacted>`.

```ts
await Sandbox.create({
  networkPolicy: {
    allow: {
      "api.github.com": {
        transform: [{ headers: { authorization: `Bearer ${token}` } }],
      },
    },
  },
});
```

A rule turns TLS inspection on, because the proxy has to terminate TLS to touch
a request. The guest is handed the inspection CA during its first handshake, so
this only works at create time: adding a rule to a sandbox created without
inspection throws `failed_precondition` rather than silently doing nothing.

#### Narrowing a rule with `match`

Without a `match`, a rule applies to every request to its domain. Add one to
narrow it to a path, a method, query entries or headers.

```ts
await Sandbox.create({
  networkPolicy: {
    allow: {
      "api.github.com": [
        {
          match: { path: { startsWith: "/repos/" }, method: ["GET"] },
          transform: [{ headers: { authorization: `Bearer ${token}` } }],
        },
      ],
    },
  },
});
```

**A matcher never blocks.** It selects which requests the rule acts on. A
request matching no rule is still allowed and still reaches the origin; it just
goes out unmodified. To refuse a request, leave its domain out of `allow`, or
forward the domain to an endpoint that refuses it.

`path`, `queryString` values and `headers` values each take a bare string,
which is an exact match, or one of `{ exact }`, `{ startsWith }` or
`{ regex }`. Paths, methods and header values are compared case-sensitively;
header names are not. Query and header entries are ANDed, and a repeated key
matches if any of its values does.

Give a domain a list of rules to have several. They are evaluated in order and
the first match wins, so a rule with no `match` shadows everything after it for
that domain: write the narrow ones first.

Rules are validated before anything is sent, because a rule that was quietly
dropped would widen a credential from one path to a whole domain. All of these
throw `invalid_argument`: an unknown key on a rule or a matcher, `transform` and
`forwardURL` on the same rule, a `match` with neither action, a rule naming a
domain that is not in `allow`, a header name that is not an RFC 9110 token, and
a `forwardURL` that is not `http(s)://` or that carries a query string or a
fragment.

#### Forwarding with `forwardURL`

A rule may instead send the requests it selects to an endpoint you control.

```ts
await Sandbox.create({
  networkPolicy: {
    allow: {
      "api.github.com": {
        forwardURL: "https://gate.example.com/inspect",
        forwardSecret: process.env.GATE_SECRET,
      },
    },
  },
});
```

The forwarded request keeps its method, headers and body, and its target is the
forward URL's path followed by the original path and query. The origin never
sees it. A `forwardURL` with no `match` is how you restrict a domain to
specific paths: everything goes through your endpoint, and your endpoint
rejects what you do not want.

Your endpoint is told where the request came from, in headers the guest cannot
forge: `burrow-forwarded-host`, `-scheme`, `-port`, `-path` and `-sandbox`,
plus `burrow-forwarded-secret` when you set `forwardSecret`.

`forwardURL` takes an `http://` or an `https://` endpoint. With `https://`,
burrow verifies the endpoint's certificate against the public roots, and there
is no way to turn that off or to name your own authority. With `http://`, the
request and the secret go out in the clear, which is reasonable only for an
endpoint the node alone can reach.

Read that secret for exactly what it is. Burrow has no OIDC issuer, so a
forwarded request is not signed. The secret proves the request came from a node
holding the rule; it authenticates the node, not the sandbox, and it is a
bearer token rather than a signature over the request. `https://` keeps it off
the wire in the clear, but an endpoint that leaks it is still compromised, and
the endpoint must not be given authority that a node compromise should not also
grant. See [FIREWALL.md](../../docs/FIREWALL.md) for the full statement and the
limits.

| Shorthand | Burrow policy |
|---|---|
| `"allow-all"` | `mode: "open"` |
| `"deny-all"` | `mode: "none"` |
| `allow: [...]` | `mode: "allowlist"`, `allowDomains` |
| `allow: { domain: { transform } }` | `allowDomains` plus a `setHeaders` rule, `inspectTls: true` |
| `allow: { domain: { match, transform } }` | The same rule, narrowed to the requests the matcher selects |
| `allow: { domain: { forwardURL } }` | `allowDomains` plus a `forward` rule, `inspectTls: true` |
| `subnets.allow` | `allowCidrs` |
| `subnets.deny` | `denyCidrs` |

Pass an object for the full policy.

```ts
await Sandbox.create({
  network: {
    mode: "allowlist",
    allowDomains: ["api.github.com"],
    allowCidrs: ["10.0.0.0/8"],
    allowPorts: [443],
    denyCidrs: ["169.254.0.0/16"],
    inspectTls: true,
    injectHeaders: [
      { domain: "api.github.com", name: "authorization", value: `Bearer ${token}` },
    ],
  },
});
```

| Field | What it does |
|---|---|
| `mode` | `"none"`, `"allowlist"`, or `"open"` |
| `allowDomains` | Domain globs reachable in allowlist mode |
| `allowCidrs` | Extra destinations permitted at the IP layer |
| `allowPorts` | Destination ports permitted |
| `denyCidrs` | Ranges the sandbox may never reach, in any mode |
| `inspectTls` | Terminate the sandbox's TLS so the host inside the session is checked, not just the SNI |
| `rules` | What the host does to the requests it inspects, in order |
| `injectHeaders` | Credentials the host attaches on the sandbox's behalf, appended after `rules` |

Deny beats every allowance. An allowed domain that resolves into a denied range
is refused.

`rules` is the full form of what `allow: { domain: { ... } }` builds, for code
that would rather write the rules directly:

```ts
await Sandbox.create({
  network: {
    mode: "allowlist",
    allowDomains: ["api.github.com"],
    inspectTls: true,
    rules: [
      {
        domain: "api.github.com",
        match: { path: { startsWith: "/repos/" }, method: ["GET"] },
        setHeaders: { authorization: `Bearer ${token}` },
      },
      {
        domain: "api.github.com",
        forward: { url: "http://gate.internal:8080/", secret: gateSecret },
      },
    ],
  },
});
```

Rules need `inspectTls`, because the proxy has to terminate TLS to read a
request at all. A secret never leaves the node: code in the guest uses the
credential without ever holding it, and every read of the policy returns
injected values and forward secrets redacted. Reading a policy back gives you
`rules` in full; `injectHeaders` still reports the subset of them that is a
matcher-less header injection.

### Private networks

Sandboxes that share a private network address each other by name, whatever
their egress policy. Non-members cannot reach them and cannot even resolve them,
because a lookup from outside the network answers `NXDOMAIN`.

```ts
const api = await Sandbox.create({ networks: ["team"], alias: "api" });
const worker = await Sandbox.create({ networks: ["team"], alias: "worker" });

await worker.runCommand("curl -s http://api.team.internal:8080/health");
```

Each member also answers to `<sandboxId>.<network>.internal` whether or not you
set an alias, and to the short `<alias>.internal`, resolved against the networks
the caller belongs to.

For finer control, pass membership objects.

```ts
await Sandbox.create({
  networks: [{ network: "team", alias: "api", ingressPorts: [8080], allowEgress: false }],
});
```

## Update a running sandbox

`update` changes tags, the network policy, the exec and file policies, or any
combination. Each section named is replaced wholesale rather than merged, so one
call is enough to lock a sandbox down or to retag it.

```ts
await sandbox.update({
  tags: { owner: "ci", stage: "locked-down" },
  networkPolicy: "none",
  exec: { allowExec: false },
});
```

Firewall rules, proxy allowlist, DNS filtering, and header injection all
re-render at once, so the sandbox is never briefly half-governed.

Call the pieces directly if you prefer.

```ts
await sandbox.updateTags({ owner: "ci" });
await sandbox.updateNetworkPolicy({ mode: "allowlist", allowDomains: ["pypi.org"] });
await sandbox.updateAccessPolicy({ fs: { allowUpload: false, pathScopes: ["/work"] } });
```

### Exec and file policy

`exec` and `fs` are enforced on the node, before a command or a path reaches
the guest, so a change takes effect on the next call and the sandbox is never
disturbed.

```ts
await sandbox.updateAccessPolicy({ exec: { allowExec: false } });
```

What each section's presence means is the part to hold on to, because it is
deliberately not what it means on create:

- A section you pass **replaces that section wholesale**. A field you leave out
  of it is an allowance withdrawn, so restate the parts you want kept: `fs:
  { allowUpload: false }` also reopens the path scopes and clears the upload
  cap.
- A section you omit is **left exactly as it is**. It does not become "allow
  everything".

Tightening files therefore never re-opens exec. On create the opposite holds,
where an omitted section is what an unrestricted sandbox looks like; reading an
update the same way would make locking down files a silent loosening of
something else. Naming neither section throws `invalid_argument` rather than
doing nothing.

The clocks a sandbox is measured against move too, so work that turns out to
need longer is not stuck with the budget it was created under.

```ts
await sandbox.update({ maxLifetimeSecs: 7200, idleSuspendSecs: 900 });
await sandbox.extendTimeout(60 * 60 * 1000); // the familiar spelling
```

A lifetime is a total measured from when the sandbox was created rather than an
amount added to what is left, so pass the whole budget you want it to have had.
An omitted field is left where it is, which is what lets `0` keep meaning
"unlimited" here as it does on create. The reaper reads the policy on its next
pass, so an extension takes effect without restarting anything.

The machine shape is not updatable at all: `vcpus`, memory and disk are not
fields on an update, because a running VM's configuration is fixed and a restore
takes its shape from the snapshot. Create a new sandbox, or a snapshot and a
sandbox from it, at the shape you want.

## Expose ports

```ts
await sandbox.runCommand("sh", ["-c", "python3 -m http.server 8000 &"]);

const { url } = await sandbox.exposePort(8000);
// -> http://<node>:20000

await sandbox.listPorts();
await sandbox.closePort(20000);

await sandbox.domain(8000); // "8000-sbx_2f0c.sandbox.example.com" or "<node>:20000"
```

`domain` tells you where a published port answers, and throws `not_found` when
the port is not published.

The edge router is a per-node thing, turned on with `burrowd serve
--edge-domain`. When the node holding the sandbox runs one, every mapping
carries an `edgeUrl` alongside `url`, a per-sandbox hostname of the form
`http://<port>-<sandbox-id>.<edge-domain>/`, and traffic arriving on it wakes a
stopped sandbox, which is what makes `idleSuspendSecs` safe to turn on behind a
published port. Only that node can answer the hostname, so a sandbox that ends
up on a node without an edge has no `edgeUrl` at all and `domain` falls back to
the bare `host:port` of the node.

## Stop, resume, and fork

`stop` snapshots the sandbox, memory and processes and filesystem, and shuts its
VM down. `resume` restores it from that snapshot rather than booting, and
running processes carry on where they left off.

```ts
await sandbox.stop();
// minutes or days later, possibly from a different process
const again = await Sandbox.get({ id: sandbox.id });
await again.resume();
```

You rarely need to call `resume` yourself. A call that needs a running VM
resumes the sandbox and retries once. Set `autoResume: false` on
`Sandbox.create`, `Sandbox.get`, or a single `runCommand` to turn that off, in
which case the call fails with `failed_precondition` and `err.isSuspended` is
true.

`fork` creates a new sandbox from another one's current state. The source keeps
running, and its state is written first, so the child starts from the state as
of the call.

```ts
const child = await sandbox.fork();
const locked = await sandbox.fork({ networkPolicy: "none" });
const named = await sandbox.fork({ name: "api-canary" });

// or, without a handle on the parent
const other = await Sandbox.fork({ source: "api" });
```

The child inherits the source's policy and tags unless you override them, lands
on the same node, and gets its own filesystem and address. It does not inherit
the source's name, because a name belongs to one sandbox. It cannot be reshaped
either: a restored VM takes its vcpus and memory from the snapshot, so a fork
asking for a different shape is refused.

| Method | What happens to the VM | Can you resume it |
|---|---|---|
| `snapshot()` | Briefly paused, then keeps running | Already running |
| `stop()` / `pause()` | Snapshotted, then shut down | Yes, with `resume()` |
| `delete()` | Destroyed, disk released | No |

There is no `checkpoint()`. Burrow can write a running guest's memory without
stopping it, and `fork` and `snapshot` both do, but memory on its own is not a
restore point: the guest keeps writing to its disk, so the pair stops agreeing
the moment it resumes. Take a `snapshot()` when you want a point to come back
to, which copies the disk alongside the memory.

`stop` returns the sandbox record as it stands afterwards, carrying the cpu and
bytes the sandbox has used. See [Usage](#usage).

A deleted handle is inert. Every later call throws `failed_precondition`
immediately rather than failing somewhere deeper against an id that is gone.

## Sessions

A session is one VM boot inside a sandbox's life. A sandbox outlives its VMs:
`stop` ends one and `resume` starts the next, and a fork or a create from a
snapshot starts one from state written elsewhere.

```ts
const sessions = await sandbox.listSessions();
// [{ id, sandboxId, startedBy: "resume", endedBy: "", startedAt, endedAt: "" }, ...]

const [newest] = sessions;                     // newest first
const restarts = sessions.length - 1;

const current = await sandbox.currentSession();
// the open session, or undefined once the sandbox is stopped
```

`currentSession` is the session with no `endedAt`. It is a filter over the list,
with its own name because that is how the question gets asked: how long has this
one been up, not which of every VM this sandbox has run is still going.

`startedBy` is `boot` from a template, `restore` from a fork or a snapshot, or
`resume` from the sandbox's own stop state, and `unknown` for anything a newer
server reports that this client does not recognise. `endedBy` is `""` while the
VM is running, then `suspended`, `deleted`, `failed`, or `unknown` for a session
that was open when its node died. An `unknown` session has an empty `endedAt`,
because nothing recorded when its VM stopped.

Each node keeps the 64 most recent sessions of a sandbox and evicts the oldest,
so a long-lived sandbox does not grow the list without bound. The list belongs
to the sandbox and goes when you delete it.

## Usage

Every sandbox record carries what it has actually consumed, totalled across
every VM it has run, so a stop and a resume do not reset it.

```ts
await sandbox.refresh();
sandbox.usage;
// { cpuUsageUsec: 5_550_000, rxBytes: 571_300, txBytes: 571_200 }
```

`cpuUsageUsec` is read from the cgroup that already caps the sandbox, so it
covers the whole VM: the guest's vCPU threads and Firecracker's own work for
them. It does not include host work done outside that cgroup, such as the egress
proxy's share of a request the sandbox made.

`rxBytes` and `txBytes` are counted at the sandbox's tap, which is where the
guest's own traffic is. Egress that goes through the host proxy is counted once,
as the guest sent it, rather than again as the proxy forwarded it. Traffic the
policy went on to drop is still counted, because what a sandbox tried to send is
part of what it cost.

Figures are as fresh as the node's last sample, which is at most a few seconds
old. A sandbox that never ran anything reports zeroes, and a forked child starts
from zero: a restore copies state, not the bill for producing it.


## Volumes

Storage that outlives the sandboxes mounting it.

```ts
import { Sandbox, Volume } from "@pixec/burrow";

const cache = await Volume.create("build-cache", { sizeMib: 20_480 });

const sbx = await Sandbox.create({
  template: "python",
  volumes: [{ volume: "build-cache", path: "/cache" }],
});
```

A volume is an ext4 image on one node, attached to the guest as a block device,
because that is the only storage Firecracker offers. Three rules follow, and
none of them are avoidable:

- **Writable mounts are exclusive.** One sandbox at a time may mount a volume
  read-write; a second create is refused with the holder's id. The claim is
  released when that sandbox stops, so a volume hands off between jobs.
- **Read-only mounts are shared with each other.** Any number of sandboxes may
  mount one read-only at once (`readOnly: true`), but not while a writer holds
  it, and a writer is refused while anything is reading. A filesystem a writer
  has mounted has a dirty journal, which a read-only mount cannot replay.
- **A volume never moves.** The sandbox is placed on the node holding it.
  Mounting one costs nothing in create latency: the node hotplugs it onto the
  restored VM and the agent mounts it during the handshake.

Mount paths must be absolute, may not overlap each other, and may not sit
inside `/proc`, `/sys`, `/dev`, `/tmp`, `/run`, `/etc`, `/usr` or `/bin`. At
most 8 per sandbox.

```ts
await Volume.list();                       // every volume
await Volume.list({ node: "node-a" });     // one node's
const v = await Volume.get("build-cache"); // v.attachedTo is read from the node
await v.delete();                          // refused while a sandbox holds it
```

`Volume.create` places the volume like a sandbox, so `nodeLabels` is the only
chance to say where it lives:

```ts
await Volume.create("fast-cache", { nodeLabels: { disk: "nvme" } });
```

See [VOLUMES.md](../../docs/VOLUMES.md).

## Snapshots

A snapshot keeps a sandbox's state as an object of its own. Start any number of
sandboxes from it, including after the sandbox it came from is gone.

```ts
import { Sandbox, Snapshot } from "@pixec/burrow";

const snapshot = await sandbox.snapshot();          // the sandbox keeps running
const restored = await Sandbox.create({ snapshot: snapshot.id });

await Snapshot.list({ sandbox: sandbox.id });
await Snapshot.get(snapshot.id);
await snapshot.delete();
```

A sandbox created from a snapshot restores rather than boots, so it arrives with
the processes and memory the source had. It takes its template and machine shape
from the snapshot, so passing a `template` or `resources` that disagree is
refused rather than quietly ignored.

Snapshots are node-local, because one encodes host cpu features and the exact
Firecracker version. A create from a snapshot is placed on the node holding it.

Bound how much disk they hold with three `resources` fields, set when the
sandbox is created:

| Field | Effect | Default |
|---|---|---|
| `snapshotExpirationSecs` | Sweep a snapshot this long after it was last used | `0`, keep indefinitely |
| `keepLastSnapshots` | Keep only this many snapshots of the sandbox | `0`, unlimited; 1 to 10 otherwise |
| `keepEvictedSnapshots` | Let an evicted snapshot expire on its own instead of being deleted at once | `false`, evictions delete |

```ts
const sbx = await Sandbox.create({
  name: "build-env",
  resources: {
    keepLastSnapshots: 2,
    snapshotExpirationSecs: 7 * 24 * 60 * 60,
    keepEvictedSnapshots: true,
  },
});
await sbx.snapshot({ expiration: 3600 }); // wins over the sandbox default
```

All three live under `resources`, not at the top level, so a create that sets
them anywhere else silently keeps the defaults.

`keepEvictedSnapshots` releases an evicted snapshot rather than deleting it: it
stops counting toward `keepLastSnapshots` and stays restorable until its own
expiration sweeps it. It requires the other two fields, and a create that sets
it without them is refused, because with no cap nothing is evicted and with no
expiry a released snapshot is never reclaimed.

The expiry clock runs from last use and is refreshed whenever a sandbox is
created from the snapshot, so one you keep using stays.

## Build templates

Packages you install at runtime die with the sandbox. Bake them into a template
and every sandbox starts with them.

```ts
import { Template, defaultBuildLogger } from "@pixec/burrow";

const template = Template()
  .fromTemplate("default")
  .aptInstall(["python3", "python3-pip"])
  .pipInstall(["cowsay", "requests"])
  .writeFile("/etc/motd", "built by burrow\n");

await Template.build(template, "python-tools", {
  cpuCount: 2,
  memoryMB: 2048,
  onBuildLogs: defaultBuildLogger(),
});

const sandbox = await Sandbox.create({ template: "python-tools" });
```

Steps run in a real sandbox and the filesystem they leave behind becomes the
image. There is no separate build language. A step that exits non-zero fails the
build, so a broken step never gets baked in. Builds default to 1 vCPU, 1024 MiB,
a 30 minute timeout, and unrestricted egress, because installing packages needs
it; pass `allowDomains` to narrow the egress.

`Template.list()` and `Template.delete(name)` manage what exists. Inspect a plan
before building it with `template.plan`. Also available: `runCmd`, `apkInstall`,
`npmInstall`, `mkdir`, and `workdir`, which despite the name only creates the
directory. Steps do not inherit a working directory, so `cd` inside the step
that needs one.

### Start from an OCI image

```ts
const template = Template()
  .fromImage("python:3.12-slim")
  .pipInstall(["requests"]);

await Template.build(template, "py-requests", { onBuildLogs: defaultBuildLogger() });
```

The image is pulled and converted on the node. Its layers become the root
filesystem and burrow's agent is installed as the VM's init. The image's `Env`
and `WorkingDir` carry over, so commands see the `PATH` the image intended.
Entrypoint, user, and signal handling do not, because a sandbox is a VM whose
PID 1 is burrow's agent rather than a container running the image's process.

### Warm templates

Nodes warm templates themselves. A template is pre-booted and snapshotted as
soon as it lands, so later creates restore instead of booting: a warm create is
around 45ms against seconds for a cold boot. `Template.list` reports whether a
template is warm.

Restores are fully independent, with separate filesystems, separate addresses,
and independent randomness. They are still clones, so anything running at the
moment the snapshot was taken is running in all of them.

A template is built on one node, and the orchestrator replicates it to another
node when it needs to place a sandbox there. Warm snapshots do not travel, since
one encodes host cpu features and the exact Firecracker version, so the
receiving node warms the template again itself.

## Manage many sandboxes

`Sandbox.create` opens its own connection. Use `Burrow` to share one.

```ts
import { Burrow } from "@pixec/burrow";

const burrow = new Burrow({ endpoint: "localhost:7070" });

const sandbox = await burrow.create({ network: "open" });
const running = await burrow.list({ tag: "owner=ci" });
const existing = await burrow.get(running[0].id);
const nodes = await burrow.nodes();

burrow.close();
```

`burrow.health()` checks the orchestrator is answering, and a `Burrow` also
works with `using` for scope-bound cleanup.

## Choose where a sandbox runs

Burrow is self-hosted, so there are no regions to pick from. What there is
instead: operators label their machines, and you constrain placement to labels.

```ts
// on each machine: burrowd serve --label rack=b7 --label tier=dedicated
const nodes = await burrow.nodes();
// [{ id: "node_b", labels: { rack: "b7", tier: "dedicated" }, ... }]

const sandbox = await burrow.create({ nodeLabels: { rack: "b7" } });
const child = await sandbox.fork({ nodeLabels: { rack: "b7" } });
```

A create carrying labels lands only on a node carrying every one of them,
matched as whole pairs. No node carrying them all fails with
`failed_precondition` naming the labels nothing satisfies, rather than putting
your workload somewhere you did not ask for. Use it for rack or host affinity,
for keeping a workload beside the data or the disk it needs, or for giving a
tenant dedicated hardware.

`fork` takes the same option, but it cannot move the child: a fork is built
where its source's state already is, so the labels are a precondition on the
source's node.

## Read the audit trail

Every connection attempt and DNS lookup a sandbox makes is recorded.

```ts
const denied = await burrow.audit({ deniedOnly: true, limit: 20 });
for (const event of denied) {
  console.log(event.at, event.sandboxId, event.host, event.reason);
}
```

Lookups are permitted in every network mode, so a sandbox that tried to reach a
blocked host shows up twice: the DNS query that resolved it, and the connection
the proxy refused.

## Cancel calls

Most methods take an optional `signal`. The exceptions are the ones with no
call of their own to cancel or no options object to hold it: `mkDir`, `watch`,
`terminal`, `asUser`, and the string form of `readFile`.

```ts
const controller = new AbortController();
setTimeout(() => controller.abort(), 5000);

await sandbox.runCommand("sleep", ["60"], { signal: controller.signal });
```

An aborted call rejects with a `BurrowError` whose code is `cancelled`.

## Configure the client

| Option | Default | What it does |
|---|---|---|
| `endpoint` | `$BURROW_ENDPOINT`, else `localhost:7070` | Orchestrator address |
| `apiKey` | `$BURROW_API_KEY` | Sent as `authorization: Bearer ...`. Required when the orchestrator runs with `--api-key` |
| `tls` | `true` for `https://` endpoints | Whether to use TLS |
| `timeoutMs` | `60000` | Default per-call deadline |

## Handle errors

Failures throw `BurrowError` with a stable `code`, so you can branch without
knowing the transport.

```ts
import { BurrowError } from "@pixec/burrow";

try {
  await Sandbox.get({ id: "sbx_missing" });
} catch (err) {
  if (err instanceof BurrowError && err.code === "not_found") {
    // ...
  }
}
```

Codes are `not_found`, `already_exists`, `invalid_argument`,
`failed_precondition`, `permission_denied`, `unauthenticated`,
`resource_exhausted`, `unavailable`, `unimplemented`, `deadline_exceeded`,
`cancelled`, and `internal`.

`CommandFailedError` extends `BurrowError` and carries `exitCode`, `stdout`, and
`stderr`. It is thrown only when you pass `check: true`. Its `code` is
`internal`, so test for it with `instanceof` rather than by code.

## Read a sandbox's state

Accessors read the record from the last call that returned one. `refresh()`
re-reads it.

```ts
await sandbox.refresh();
sandbox.id;            // "sbx_b4929ded..."
sandbox.name;          // "build-482", or the id when it was never named
sandbox.status;        // "pending" | "running" | "stopping" | "stopped" | "failed"
sandbox.state;         // the full state, including "suspended" and "paused"
sandbox.template;      // also `image`
sandbox.tags;
sandbox.vcpus;
sandbox.memory;        // MiB; also `memoryMib`
sandbox.createdAt;     // RFC 3339
sandbox.networkPolicy; // the policy in force, injected values redacted
sandbox.nodeId;
sandbox.unreachable;   // true when the hosting node has missed its heartbeats
sandbox.usage;         // { cpuUsageUsec, rxBytes, txBytes }
```

| Accessor | Notes |
|---|---|
| `id` | Assigned by the orchestrator, `sbx_` and a uuid |
| `name` | The name it was created with, falling back to `id` when it has none |
| `status` | The five-state view. `suspended`, `paused` and `destroyed` all read as `stopped`, and a state this client does not recognise reads as `failed` |
| `state` | Burrow's own state, when the difference matters |
| `template`, `image` | The same string |
| `tags`, `metadata` | The same map |
| `vcpus`, `memory`, `memoryMib` | From the policy in force |
| `createdAt` | There is no `updatedAt`: the record does not carry one |
| `networkPolicy`, `policy` | Injected header values arrive `<redacted>` |
| `unreachable` | The hosting node has missed its heartbeats, so `state` is the last reading it reported. Calls fail with `unavailable` until it returns, except `delete()` |
| `usage` | What the sandbox has consumed, across every VM it has run. See [Usage](#usage) |

## Method reference

| Method | RPC |
|---|---|
| `Sandbox.create` | `CreateSandbox` |
| `Sandbox.getOrCreate` | `GetSandbox`, then `CreateSandbox` |
| `Sandbox.get`, `sandbox.refresh` | `GetSandbox` |
| `Sandbox.list` | `ListSandboxes` |
| `Sandbox.fork`, `sandbox.fork` | `ForkSandbox` |
| `sandbox.runCommand`, `exec`, `execStream`, `terminal`, `asUser` | `Exec` |
| `sandbox.listCommands` | `ListCommands` |
| `sandbox.getCommand` | `GetCommand`, then `AttachCommand` per `logs()` |
| `command.kill`, `killed` | `SignalCommand` |
| `sandbox.createUser`, `createGroup` | `CreateUser`, `CreateGroup` |
| `sandbox.addUserToGroup`, `removeUserFromGroup` | `AddUserToGroup`, `RemoveUserFromGroup` |
| `sandbox.writeFile`, `writeFiles` | `UploadFile`, one per file |
| `sandbox.readFile`, `readFileToBuffer`, `readFileBytes`, `downloadFile` | `DownloadFile` |
| `sandbox.listDir` | `ListDir` |
| `sandbox.mkDir` | `Exec`, running `mkdir -p` |
| `sandbox.watch` | `Watch` |
| `sandbox.exposePort`, `listPorts`, `closePort`, `domain` | `ExposePort`, `ListPorts`, `ClosePort` |
| `sandbox.update`, `updateTags` | `UpdateTags` |
| `sandbox.update`, `updateNetworkPolicy` | `UpdateNetworkPolicy` |
| `sandbox.update`, `updateResources`, `extendTimeout` | `UpdateResources` |
| `sandbox.update`, `updateAccessPolicy` | `UpdateAccessPolicy` |
| `sandbox.listSessions`, `currentSession` | `ListSessions` |
| `sandbox.stop`, `pause` | `PauseSandbox` |
| `sandbox.resume` | `ResumeSandbox` |
| `sandbox.delete`, `kill` | `DeleteSandbox` |
| `sandbox.snapshot`, `Snapshot.list`, `get`, `delete` | `CreateSnapshot`, `ListSnapshots`, `GetSnapshot`, `DeleteSnapshot` |
| `Template.build`, `list`, `delete` | `BuildTemplate`, `ListTemplates`, `DeleteTemplate` |
| `burrow.audit` | `QueryAudit` |
| `burrow.nodes`, `drainNode` | `ListNodes`, `DrainNode` |
| `burrow.health` | `Health` |

## Migrating from earlier versions

`sandbox.checkpoint()` is gone. Memory written without the disk is not a restore
point, and the guest keeps writing to its disk the moment it resumes, so the two
halves stop agreeing. Use `sandbox.snapshot()`, which copies both, or
`sandbox.fork()`, which does the same into a new sandbox. Both still write the
source's state without stopping it.

Everything else changed meaning or gained a better spelling rather than going
away.

| Before | Now | Note |
|---|---|---|
| `sandbox.kill()` | `sandbox.delete()` | `kill` still works and still destroys |
| `sandbox.pause()` | `sandbox.stop()` | Both suspend. `stop` does not destroy |
| `sandbox.exec()` | `sandbox.runCommand()` | `exec` still returns `stdout` and `stderr` as strings |
| `sandbox.mkdir()` | `sandbox.mkDir()` | Both work |
| `sandbox.files` | `sandbox.fs` | Both work, with different names inside |
| `Sandbox.connect(id)` | `Sandbox.get({ id })` | Both work |
| `metadata` | `tags` | Both are accepted and both are readable |

## Development

```sh
npm install
npm run build        # syncs protos from the workspace, then compiles
npm run typecheck
node examples/quickstart.mjs   # needs a running burrow stack
```
