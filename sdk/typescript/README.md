# @pixec/burrow

Run untrusted code in Firecracker microVMs from Node.

```sh
npm install @pixec/burrow
```

The SDK talks gRPC to a [burrow](../../) orchestrator. It needs Node 18 or newer
and depends only on `@grpc/grpc-js` and `@grpc/proto-loader`.

It mirrors Node rather than inventing an API: `sandbox.fs` is
`node:fs/promises`, `FileHandle` included, and `sandbox.childProcess` is
`node:child_process`, with the same signatures, return types and errors. Code
written against Node works against a sandbox by changing which object it
calls. What Node has no counterpart for, such as reattaching to a command
another process started, is on `Sandbox`.

## Quickstart

Create a sandbox, run a command, and destroy it.

```ts
import { Sandbox } from "@pixec/burrow";

const sandbox = await Sandbox.create({ template: "python" });

const { stdout } = await sandbox.childProcess.execFile("echo", ["hello"]);
console.log(stdout); // "hello\n"

await sandbox.delete();
```

Use `await using` and the sandbox destroys itself when the scope exits, even if
your code throws.

```ts
await using sandbox = await Sandbox.create({ template: "python" });
await sandbox.fs.writeFile("/work/hello.py", "print('hello')\n");
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
  networkPolicy: {
    mode: "allowlist",
    allowDomains: ["pypi.org", "*.pythonhosted.org"],
  },
});
```

### Options

| Option | Default | What it does |
|---|---|---|
| `name` | none | Name for the sandbox, the only identity you choose. Ids are generated |
| `template` | none | Guest image to boot, as imported by `burrow pull`. Required unless `snapshot` is given |
| `snapshot` | none | Restore from a snapshot instead of booting a template |
| `tags` | `{}` | Up to 16 key/value pairs, used for filtering later |
| `nodeLabels` | `{}` | Labels the hosting node must carry, all of them. See [Choose where a sandbox runs](#choose-where-a-sandbox-runs) |
| `resources` | 1 vCPU, 512 MiB | Machine shape, lifetime, and snapshot retention |
| `networkPolicy` | `"none"` | Egress policy, as a mode or a full policy object |
| `env` | `{}` | Environment merged under every command this handle runs |
| `networks` | `[]` | Private networks to join |
| `alias` | sandbox id | Name this sandbox answers to on those networks |
| `exec` | everything allowed | Whether callers may run commands in the sandbox |
| `fs` | everything allowed | What callers may do to the sandbox's filesystem |
| `kit` | none | Inputs for a template pulled from a [Sandbox Kit](../../docs/TEMPLATES.md#sandbox-kits): `args`, `env` and `rejectCapabilities`. Ignored on any other template |
| `autoResume` | `true` | Resume and retry once when a call finds the sandbox stopped |
| `timeoutMs` | `120000` | How long to wait for the boot |
| `signal` | none | `AbortSignal` that cancels the call |

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
| `allowExec` | `true` | `false` refuses every command, terminal and signal on this sandbox |

| `fs` field | Default | What it does |
|---|---|---|
| `allowUpload` | `true` | `false` refuses uploads |
| `allowDownload` | `true` | `false` refuses downloads |
| `pathScopes` | `[]` | Absolute paths `fs` calls, downloads and watches are confined to. At most 16; empty is the whole filesystem |
| `maxUploadBytes` | `0` | Ceiling on a single upload or write. `0` is unlimited |

```ts
const sandbox = await Sandbox.create({
  exec: { allowExec: false },
  fs: { pathScopes: ["/work"], maxUploadBytes: 8 * 1024 * 1024 },
});
```

Scopes are matched on whole path components, so `/data` admits `/data/in.csv`
and refuses `/database/dump.sql`. A path carrying `..` is refused outright. A
path outside the scopes fails the way the kernel would refuse it, `EACCES`, and
a write past the ceiling `EFBIG`.
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
  onCreate: (s) => s.fs.writeFile("/work/app.py", source),
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

`sandbox.childProcess` is Node's `child_process`, run in the guest. `exec`,
`execFile` and `spawn` take the arguments Node's do and behave the way Node's
do, so code written against `child_process` moves over by swapping the import.

```ts
const { stdout } = await sandbox.childProcess.exec("cat /etc/hostname | tr a-z A-Z");

const { stdout: version } = await sandbox.childProcess.execFile("python3", ["--version"]);
```

These are the `util.promisify` forms: they resolve `{ stdout, stderr }` once
the command exits 0, as strings, or as Buffers with `encoding: "buffer"`.
`exec` runs its command through `/bin/sh -c`, so pipes and redirection work;
`execFile` runs the program directly, so its arguments need no quoting. The
returned promise carries the `ChildProcess` as `.child`.

Any other ending rejects with Node's error: `message` is
`Command failed: <cmd>\n<stderr>`, `code` is the exit code, and `signal`,
`killed`, `cmd`, `stdout` and `stderr` are set beside it.

```ts
try {
  await sandbox.childProcess.exec("make all");
} catch (err) {
  err.code;   // 2, or null when a signal ended it
  err.signal; // null, or "SIGTERM"
  err.stderr; // what it printed
}
```

| Option | What it does |
|---|---|
| `cwd` | Directory to run in. Defaults to the image's `WorkingDir`, or the user's home |
| `env` | Laid over the guest's environment and the handle's `env`. Nothing from this process leaks in |
| `shell` | `exec` only takes a path; `execFile` and `spawn` take `true` for `/bin/sh` or a path |
| `timeout`, `killSignal` | Kill with `killSignal`, SIGTERM by default, after this many milliseconds |
| `maxBuffer` | Bytes of stdout or stderr `exec` keeps before it kills the command. 1 MiB |
| `encoding` | `"utf8"` by default; `"buffer"` resolves Buffers |
| `signal` | `AbortSignal`. Aborting kills the command and rejects with an `AbortError` |
| `user` | Burrow only. Guest user to run as. Defaults to the handle's, which is root unless it came from `asUser` |
| `pty`, `rows`, `cols` | Burrow only. Run under a pty, so the program sees a terminal |
| `logMaxBytes`, `logMaxFiles` | Burrow only. Rotate the command's log on the node, as Docker's `max-size` and `max-file` |

Signal names are Linux's, whatever the platform this runs on: `SIGUSR1` is 10
in the guest even from a Mac, where Node's own number for it is 30.

### Environment defaults

`env` on `create` or `getOrCreate` is merged under every command that handle
runs, and a command's own `env` wins over it. `asUser` and `fork` carry it
along; `terminal()` does not, so pass a terminal's environment to the
terminal.

```ts
const sandbox = await Sandbox.create({ env: { NODE_ENV: "test" } });
await sandbox.childProcess.exec("printenv NODE_ENV"); // stdout "test\n"
```

This lives in the client, not in the sandbox. A handle from `Sandbox.get` in
another process does not have it, and nothing in the guest can read it back.
Bake anything that has to survive into the template.

### Stream output

`spawn` returns a `ChildProcess` at once: an `EventEmitter` with `stdin`,
`stdout` and `stderr` streams, as Node's is.

```ts
const child = sandbox.childProcess.spawn("npm", ["install"], { cwd: "/work" });

child.stdout.pipe(process.stdout);
child.stderr.pipe(process.stderr);
child.on("close", (code, signal) => console.log("done", code, signal));
```

Without `shell` the command is the program and no shell is involved. With
`shell: true` the command and its arguments are joined with spaces and handed
to `/bin/sh -c`, unquoted, exactly as Node does it.

Events are Node's, in Node's order: `spawn` once the guest has started the
command, `exit` with `(code, signal)`, then `close` once stdout and stderr have
ended, and `error` when it could not be started or a stream broke. A command a
signal ended reports `exitCode` null and `signalCode` `"SIGTERM"`, as Node
does. As with Node, output may still be arriving when `exit` fires, and output
nobody reads is drained so that `close` still comes.

Write to `stdin` and the bytes reach the command; `stdin.end()` sends EOF.
Pass `stdio: "ignore"`, or `["ignore", "pipe", "pipe"]`, to start it with stdin
already closed. `"inherit"` and file descriptors are not offered: there is no
descriptor of this process the guest could share.

`child.cmdId` is the command's id in the sandbox, set by the time `spawn`
fires. Keep it and another process can pick the same command up again. See
[Reattach to a command](#reattach-to-a-command). `child.pid` is always
`undefined`: the guest's process ids are not exposed.

Pass `pty: true` for programs that behave differently on a terminal, such as
anything with colour, progress bars, or a REPL.

### Interactive terminals

When input arrives over time, from a browser terminal or an agent driving a
REPL, open a terminal. It allocates a pty, keeps stdin open, and takes resizes.

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
const child = sandbox.childProcess.spawn("./train.sh");
child.on("spawn", () => queue.put({ sandbox: sandbox.id, cmdId: child.cmdId }));
```

`getCommand` hands back a `ChildProcess` attached to it. Its output is replayed
from the start and then followed live until the command exits; the node keeps
every byte. Attaching to a command that has already finished replays it and
then emits `exit` and `close`, so the same code covers both.

```ts
// Somewhere else entirely.
const sandbox = await Sandbox.get({ id: sandboxId });
const child = await sandbox.getCommand(cmdId);

child.stdout.pipe(process.stdout);
child.on("exit", (code, signal) => console.log("exited", code, signal));
```

A reader that comes back after a disconnect passes the offset it got to,
stdout and stderr bytes counted together, and is sent only what followed:

```ts
let seen = 0;
const child = await sandbox.getCommand(cmdId, { fromOffset: seen });
child.stdout.on("data", (chunk) => (seen += chunk.length));
child.stderr.on("data", (chunk) => (seen += chunk.length));
child.on("lost", (bytes) => console.warn(`${bytes} bytes are gone`));
```

`lost` is Burrow's own event. It stands for output the node cannot send: what
a rotating log dropped (see `logMaxBytes`), or what a failed write, most likely
on a full disk, never recorded.

An attached child can also feed the command. A shell started by a process that
has since gone keeps its stdin open, and takes input from the next one:

```ts
const shell = await sandbox.getCommand(shellId);
shell.stdin.write("ls /work\n");
shell.stdout.pipe(process.stdout);
```

`stdin.end()` sends EOF. Only an explicit EOF closes a command's stdin: a
stream that breaks, a client restart, or the sandbox sleeping leaves it open.
Any number of readers can attach to one command at once.

#### Signalling a command

`kill(signal)` signals the command, SIGTERM by default, by name or number, and
returns `true` unless the command has already exited. Delivery is
asynchronous: a signal the sandbox refuses arrives as the child's `error`
event, as a signal Node could not deliver does. A command that had exited by
the time the signal got there is not an error, since that is what kill wanted.

```ts
child.on("error", (err) => {
  if (err.code === "permission_denied") console.warn("exec is disabled on this sandbox");
});
child.kill("SIGINT");
```

What can fail: `permission_denied` when the sandbox's exec policy forbids
commands, since signals go through the same door as exec and a sandbox
tightened with `updateAccessPolicy({ exec: { allowExec: false } })` refuses
them too; `failed_precondition` when the sandbox is suspended; `not_found` for
a command since pruned; and transport failures when the node cannot be
reached. A signal reaches the command's whole process group. `kill(0)` sends
nothing and says whether the command is still running.

`listCommands()` returns everything the sandbox has run, oldest first.

```ts
for (const command of await sandbox.listCommands()) {
  console.log(command.cmdId, command.state, command.user, command.cmd.join(" "));
}
```

Output is kept the way Docker keeps a container's log: all of it, on the node
rather than in the sandbox, for as long as the command is listed. A command
that would print more than you want kept can rotate instead, as Docker's
`max-size` and `max-file`:

```ts
sandbox.childProcess.spawn("./serve.sh", {
  logMaxBytes: 20 * 1024 * 1024,
  logMaxFiles: 5,
});
```

Finished commands stay until `pruneCommands()` removes them and their output,
as `docker container prune` does; running ones are never touched.

```ts
const { removed, freedBytes } = await sandbox.pruneCommands();
```

## Users and groups

Every command runs as root by default. Give each agent its own user and they
stop sharing a home directory, an `~/.ssh`, and each other's temporary files.

```ts
const alice = await sandbox.createUser("alice");

alice.username; // "alice"
alice.uid;      // 1000
alice.home;     // "/home/alice", mode 0700

await sandbox.childProcess.exec("whoami", { user: "alice" });
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

await sandbox.asUser("alice").fs.writeFile(`${team.sharedDir}/note`, "hi\n");
await sandbox.asUser("bob").fs.readFile(`${team.sharedDir}/note`, "utf8");

await sandbox.removeUserFromGroup("bob", "team");
```

`asUser` returns a handle onto the same sandbox that acts as one user, which
saves passing `user` to every call.

```ts
const alice = sandbox.asUser("alice");

await alice.childProcess.exec("touch notes.txt"); // in /home/alice
await alice.fs.mkdir("/home/alice/work");
await alice.fs.writeFile("/home/alice/app.py", src);

const term = alice.terminal(); // a shell as alice
```

Commands and terminals run as the user, and every `fs` call is made as them:
the guest kernel checks each one with the user's credentials, so a user handle
cannot read a file its user could not, and what it creates is the user's.
`fs.watch` is the one exception, since the guest scans as root.

This is a boundary inside one sandbox, not a replacement for one. The users
share a kernel and a VM, and root in the guest still reaches everything. Two
workloads that must not touch each other belong in two sandboxes.

## Work with files

`sandbox.fs` is Node's `fs/promises`, performed by the guest kernel: the same
functions, the same signatures and defaults, the same return types, and the
same errors. Each call is one POSIX operation on the node's `Fs` call, so a
`stat` costs a round trip and no exec.

```ts
await sandbox.fs.mkdir("/work/src", { recursive: true });
await sandbox.fs.writeFile("/work/src/app.py", "print('hi')\n");
await sandbox.fs.writeFile("/work/run.sh", "python3 /work/src/app.py\n", { mode: 0o755 });

const text = await sandbox.fs.readFile("/work/src/app.py", "utf8");
const bytes = await sandbox.fs.readFile("/work/data.bin"); // Buffer

for (const entry of await sandbox.fs.readdir("/work", { withFileTypes: true })) {
  console.log(entry.name, entry.isDirectory() ? "dir" : "file");
}

const stats = await sandbox.fs.stat("/work/run.sh");
stats.size; stats.mode; stats.mtime; stats.isFile();

await sandbox.fs.rename("/work/draft.md", "/work/final.md");
await sandbox.fs.rm("/work/tmp", { recursive: true, force: true });
await sandbox.fs.cp("/work/src", "/work/src.bak", { recursive: true });
```

Methods are bound, so `const { readFile, writeFile } = sandbox.fs` works as the
same line against `fs/promises` does.

Errors from the kernel are shaped exactly as Node's: an `Error` whose message
reads `ENOENT: no such file or directory, open '/work/nope'`, with `code`,
`errno` (negative, as Node reports it), `syscall`, `path`, and `dest` for the
calls that take two paths. Code that branches on `err.code === "ENOENT"` keeps
working. The file policy refuses the way the kernel would: a path outside its
`pathScopes`, or uploads or downloads turned off, is `EACCES`, and a write past
its ceiling is `EFBIG`.

Flags are Node's strings, `"r"`, `"r+"`, `"w"`, `"w+"`, `"a"`, `"a+"` and the
`x` forms, or numbers from `sandbox.fs.constants`, which carries Linux's values
whatever this machine is. The synchronous `s` flags are refused.

`open` returns a `FileHandle`, with positional `read` and `write`, `stat`,
`truncate`, `sync`, `readFile`, `writeFile`, `readLines`, streams, and
`await using` support.

```ts
await using handle = await sandbox.fs.open("/work/data.bin", "r+");
const { bytesRead, buffer } = await handle.read(Buffer.alloc(16), 0, 16, 128);
await handle.write("patched", 0);
await pipeline(handle.createReadStream(), createWriteStream("./data.bin"));
```

A `position` of `null` reads or writes at the handle's own position and moves
it; a number does not move it. A closed handle rejects with `EBADF`, as Node's
does. The agent closes a handle left unused for ten minutes.

A whole-file `readFile` with the default flag, as root, takes the
`DownloadFile` stream, one call however large the file. Everything else opens
the file and reads or writes it in pieces of up to 4 MiB a call, so a big
`writeFile` costs a call per 4 MiB.

### Watch for changes

`watch` is `fs/promises`' `watch`: an async iterable of `{ eventType, filename }`,
`eventType` `"rename"` when a name appeared or went and `"change"` when a file
changed in place, `filename` relative to the watched directory.

```ts
const ac = new AbortController();
for await (const { eventType, filename } of sandbox.fs.watch("/work/src", {
  recursive: true,
  signal: ac.signal,
})) {
  if (eventType === "change") rebuild(filename);
}
```

The guest polls and reports differences every 500ms by default, which the
Burrow-only `intervalMs` option changes, floored at 50ms. A change is seen
within about one interval, and a file created and deleted between two scans is
not seen at all. Only directories can be watched. Aborting `signal` ends the
loop with an `AbortError`, as Node's does.

## Control the network

Sandboxes have no network by default. Access is opt-in.

```ts
await Sandbox.create({ template: "python" });  // no egress at all
await Sandbox.create({ networkPolicy: "open" }); // unrestricted
await Sandbox.create({
  networkPolicy: {
    mode: "allowlist",
    allowDomains: ["api.github.com", "*.githubusercontent.com"],
  },
});
```

A leading `*.` is the only wildcard, and it does not cover the apex:
`*.example.com` matches `www.example.com` and `a.b.example.com` but not
`example.com`.

A policy is a mode, `"none"`, `"allowlist"` or `"open"`, or an object carrying
the whole policy.

```ts
await Sandbox.create({
  networkPolicy: {
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
| `inspectTls` | Terminate the sandbox's TLS so the host inside the session is checked as well as the SNI |
| `rules` | What the host does to the requests it inspects, in order |
| `injectHeaders` | Credentials the host attaches on the sandbox's behalf, appended after `rules` |

Deny beats every allowance. An allowed domain that resolves into a denied range
is refused.

### Request rules

A rule acts on the inspected requests to one domain. `setHeaders` sets headers
on them, which is header injection: the value stays on the node, and reading
the policy back gives you `<redacted>`. `injectHeaders` is the same thing as a
rule with no matcher.

```ts
await Sandbox.create({
  networkPolicy: {
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
request at all, and the domain has to be in `allowDomains`, since only traffic
to an allowed domain is inspected. The guest is handed the inspection CA
during its first handshake, so inspection is a create-time choice: adding rules
to a sandbox created without it throws `failed_precondition` rather than
silently doing nothing. A secret never leaves the node: code in the guest uses
the credential without ever holding it, and every read of the policy returns
injected values and forward secrets redacted. Reading a policy back gives you
`rules` in full; `injectHeaders` still reports the subset of them that is a
matcher-less header injection.

#### Narrowing a rule with `match`

Without a `match`, a rule applies to every request to its domain. Add one to
narrow it to a path, a method, query entries or headers.

**A matcher never blocks.** It selects which requests the rule acts on. A
request matching no rule is still allowed and still reaches the origin; it just
goes out unmodified. To refuse a request, leave its domain out of
`allowDomains`, or forward the domain to an endpoint that refuses it.

`path`, `queryString` values and `headers` values each take a bare string,
which is an exact match, or one of `{ exact }`, `{ startsWith }` or
`{ regex }`. Paths, methods and header values are compared case-sensitively;
header names are not. Query and header entries are ANDed, and a repeated key
matches if any of its values does.

Rules are evaluated in order and the first match wins, so a rule with no
`match` shadows everything after it for that domain: write the narrow ones
first.

Rules are validated before anything is sent, because a rule that was silently
dropped would widen a credential from one path to a whole domain. All of these
throw `invalid_argument`: an unknown key on a rule or a matcher, `setHeaders`
and `forward` on the same rule, a rule with neither, a `setHeaders` naming no
header, rules with no `allowDomains`, a header name that is not an RFC 9110
token, and a forward url that is not `http(s)://` or that carries a query
string or a fragment.

#### Forwarding with `forward`

A rule may instead send the requests it selects to an endpoint you control.

```ts
await Sandbox.create({
  networkPolicy: {
    mode: "allowlist",
    allowDomains: ["api.github.com"],
    inspectTls: true,
    rules: [
      {
        domain: "api.github.com",
        forward: { url: "https://gate.example.com/inspect", secret: process.env.GATE_SECRET },
      },
    ],
  },
});
```

The forwarded request keeps its method, headers and body, and its target is the
forward URL's path followed by the original path and query. The origin never
sees it. A `forward` with no `match` is how you restrict a domain to specific
paths: everything goes through your endpoint, and your endpoint rejects what
you do not want.

Your endpoint is told where the request came from, in headers the guest cannot
forge: `burrow-forwarded-host`, `-scheme`, `-port`, `-path` and `-sandbox`,
plus `burrow-forwarded-secret` when you set `secret`.

`forward.url` takes an `http://` or an `https://` endpoint. With `https://`,
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

### Private networks

Sandboxes that share a private network address each other by name, whatever
their egress policy. Non-members cannot reach them and cannot even resolve them,
because a lookup from outside the network answers `NXDOMAIN`.

```ts
const api = await Sandbox.create({ networks: ["team"], alias: "api" });
const worker = await Sandbox.create({ networks: ["team"], alias: "worker" });

await worker.childProcess.exec("curl -s http://api.team.internal:8080/health");
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

Tags, the network policy, and the exec and file policies each have their own
call. Each replaces its section wholesale rather than merging into it.

```ts
await sandbox.updateTags({ owner: "ci", stage: "locked-down" });
await sandbox.updateNetworkPolicy({ mode: "allowlist", allowDomains: ["pypi.org"] });
await sandbox.updateAccessPolicy({ fs: { allowUpload: false, pathScopes: ["/work"] } });
```

Firewall rules, proxy allowlist, DNS filtering, and header injection all
re-render at once, so the sandbox is never briefly half-governed.

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
await sandbox.updateResources({ maxLifetimeSecs: 7200, idleSuspendSecs: 900 });
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
sandbox.childProcess.spawn("python3", ["-m", "http.server", "8000"]);

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

## Stop, resume, shut down, and fork

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
`Sandbox.create` or `Sandbox.get`, or on the handle itself, to turn that off,
in which case the call fails with `failed_precondition` and `err.isSuspended`
is true.

`fork` creates a new sandbox from another one's current state. The source keeps
running, and its state is written first, so the child starts from the state as
of the call.

```ts
const child = await sandbox.fork();
const locked = await sandbox.fork({ networkPolicy: "none" });
const named = await sandbox.fork({ name: "api-canary" });
```

The child inherits the source's policy and tags unless you override them, lands
on the same node, and gets its own filesystem and address. It does not inherit
the source's name, because a name belongs to one sandbox. It cannot be reshaped
either: a restored VM takes its vcpus and memory from the snapshot, so a fork
asking for a different shape is refused.

`shutdown` is what `docker stop` does. The VM stops and nothing in memory
survives, but the writable disk and volumes stay, and `boot` runs the image's
init again on them. For a sandbox created from a Sandbox Kit that is the stop
and start the Kit spec describes, and its startup hooks run again. A boot takes
as long as a create, since there is no memory to restore.

```ts
await sandbox.shutdown();
await sandbox.boot();
```

`recreate` replaces the root disk, discarding everything written to it, while
the sandbox keeps its id, name, address and volumes. Pass `template` to move it
onto another template, and `kit` to change the recorded Kit inputs.

```ts
await sandbox.recreate();
await sandbox.recreate({ template: "kit-9a8b7c6d5e4f3a2b", kit: { args: { team: "beta" } } });
```

| Method | What happens to the VM | Can you resume it |
|---|---|---|
| `snapshot()` | Briefly paused, then keeps running | Already running |
| `stop()` / `pause()` | Snapshotted, then shut down | Yes, with `resume()`, memory intact |
| `shutdown()` | Shut down, disks kept | Yes, with `boot()`, which runs init again |
| `recreate()` | Replaced by a fresh one on a new root disk | Already running |
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
refused rather than silently ignored.

A snapshot encodes the host's cpu architecture and the exact Firecracker
version. A create from one is placed on the node holding it. When the nodes run
with an object store (`burrowd serve --object-store`), every snapshot is also
uploaded there, and `snapshot.isDurable` turns true once the upload finishes. A
create from a durable snapshot can then be placed on any node with the same
`snapshot.arch` and `snapshot.firecrackerVersion`, including when the node that
took it is gone. `snapshot.nodeId` is empty when only the store holds it. See
[PERSISTENCE.md](../../docs/PERSISTENCE.md#snapshots).

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

An image that expects systemd can boot it under the agent. Pass
`systemd: true` and every sandbox from the template keeps the mode.
`Template.list` reports it as `systemd`. The image has to ship systemd; see
[Systemd templates](../../docs/TEMPLATES.md#systemd-templates).

```ts
await Template.build(Template().fromImage("registry.example/ubuntu-systemd:24.04"), "ubuntu-systemd", {
  systemd: true,
});
```

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

## Manage the fleet

`Burrow` is for what is not one sandbox's: health, nodes, audit, events and
secrets. Sandboxes are reached through `Sandbox`.

```ts
import { Burrow } from "@pixec/burrow";

const burrow = new Burrow({ endpoint: "localhost:7070" });
const nodes = await burrow.nodes();
burrow.close();
```

`burrow.health()` checks the orchestrator is answering, and a `Burrow` also
works with `using` for scope-bound cleanup.

### Secrets

Sandbox Kits ask for credentials by service name. A `Burrow` stores them. The
value stays on the node and is injected into matching requests by the egress
proxy, so a guest never holds it. See
[Credentials brokering](../../docs/FIREWALL.md#credentials-brokering).

```ts
await burrow.setSecret("github", process.env.GITHUB_TOKEN);
await burrow.listSecrets(); // ["github"], values are never returned
await burrow.deleteSecret("github");
```

## Choose where a sandbox runs

Burrow is self-hosted, so there are no regions to pick from. What there is
instead: operators label their machines, and you constrain placement to labels.

```ts
// on each machine: burrowd serve --label rack=b7 --label tier=dedicated
const nodes = await burrow.nodes();
// [{ id: "node_b", labels: { rack: "b7", tier: "dedicated" }, ... }]

const sandbox = await Sandbox.create({ nodeLabels: { rack: "b7" } });
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

## Follow lifecycle events

The orchestrator keeps one ordered log of what happened to every sandbox:
`created`, `started`, `agent_ready`, `stopped`, `destroyed`,
`snapshot_created`, and `recovered` for each sandbox a node finds on restart.
`burrow.events()` replays it oldest first and, with
`follow`, keeps yielding new events as they happen.

```ts
let after = 0;
for await (const event of burrow.events({ after, sandbox: "build-482", follow: true })) {
  console.log(event.seq, event.type, event.state, event.detail);
  after = event.seq; // resume from here after a disconnect
}
```

`detail` says how a VM started (`boot`, `restore`, `resume`) or stopped
(`suspended`, `deleted`, `stopped`, `failed`), what a sandbox was created from
(`fork:<id>`, `snapshot:<id>`), or the snapshot a commit produced. Each event
also carries the sandbox's `cpuUsageUsec`, `rxBytes`, `txBytes`, `vcpus` and
`memoryMib` at that instant. Without `follow` the iterator ends after the
replay; `limit` caps how many events are replayed. Break out of the loop or pass
a `signal` to stop following. See
[The event log](../../docs/ARCHITECTURE.md#the-event-log).

## Read usage

The usage ledger holds the intervals each sandbox spent in one state at one
shape, built from those events, and outlives the sandboxes it describes.
`burrow.usage()` returns the intervals, or with `groupBy` (`sandbox`,
`template`, `node`, `state` or a tag key) their sums per group and state.

```ts
const { sums } = await burrow.usage({
  from: new Date("2026-10-01"),
  to: new Date("2026-11-01"),
  groupBy: "customer",
});
for (const sum of sums) {
  console.log(sum.group, sum.state, sum.vcpuMs / 3_600_000, sum.txBytes);
}
```

An interval belongs to the window it started in. Without `groupBy`, pass
`nextAfterId` back as `afterId` to page through an export. See
[METERING.md](../../docs/METERING.md).

## Cancel calls

Most methods take an optional `signal`. The exceptions are the ones with no
call of their own to cancel or no options object to hold it: `terminal`,
`asUser`, and the `fs` functions whose Node signature has no options.

```ts
const controller = new AbortController();
setTimeout(() => controller.abort(), 5000);

await sandbox.childProcess.exec("sleep 60", { signal: controller.signal });
await sandbox.fs.readFile("/work/big.log", { signal: controller.signal });
```

The `fs` and `childProcess` calls reject as Node's do, with an `AbortError`;
an aborted `exec` also kills the command. Every other aborted call rejects
with a `BurrowError` whose code is `cancelled`.

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

`sandbox.fs` and `sandbox.childProcess` are the exception, as Node's own
modules are: a kernel error is Node's `ENOENT`-style error, and a failed
`exec` rejects with Node's `Command failed` error. See
[Work with files](#work-with-files) and [Run commands](#run-commands). What
the sandbox itself refuses, a policy denial or a suspended sandbox, is still a
`BurrowError`.

## Read a sandbox's state

Accessors read the record from the last call that returned one. `refresh()`
re-reads it.

```ts
await sandbox.refresh();
sandbox.id;            // "sbx_b4929ded..."
sandbox.name;          // "build-482", or the id when it was never named
sandbox.state;         // "running", "suspended", "stopped", ...
sandbox.template;
sandbox.tags;
sandbox.vcpus;
sandbox.memoryMib;
sandbox.createdAt;     // RFC 3339
sandbox.policy;        // the policy in force, injected values redacted
sandbox.nodeId;
sandbox.unreachable;   // true when the hosting node has missed its heartbeats
sandbox.usage;         // { cpuUsageUsec, rxBytes, txBytes }
```

| Accessor | Notes |
|---|---|
| `id` | Assigned by the orchestrator, `sbx_` and a uuid |
| `name` | The name it was created with, falling back to `id` when it has none |
| `state` | A state this client does not recognise reads as `unknown` |
| `vcpus`, `memoryMib` | From the policy in force |
| `createdAt` | There is no `updatedAt`: the record does not carry one |
| `policy` | Injected header values arrive `<redacted>` |
| `unreachable` | The hosting node has missed its heartbeats, so `state` is the last reading it reported. Calls fail with `unavailable` until it returns, except `delete()` |
| `usage` | What the sandbox has consumed, across every VM it has run. See [Usage](#usage) |

## Method reference

Calls marked "on the node" go to the node holding the sandbox by default, with
a token the SDK gets from the orchestrator's `IssueAccess` and reuses until it
nears expiry; the orchestrator carries none of that traffic, and the node has
to be reachable from where the SDK runs. Open the connection with
`route: "orchestrator"` (or set `BURROW_ROUTE=orchestrator`) and the
orchestrator relays the same calls instead. Neither falls back to the other.
Everything else goes to the orchestrator.

| Method | RPC |
|---|---|
| `Sandbox.create` | `CreateSandbox` |
| `Sandbox.getOrCreate` | `GetSandbox`, then `CreateSandbox` |
| `Sandbox.get`, `sandbox.refresh` | `GetSandbox` |
| `Sandbox.list` | `ListSandboxes` |
| `sandbox.fork` | `ForkSandbox` |
| `childProcess.spawn`, `exec`, `execFile`, `sandbox.terminal` | `Exec` on the node |
| `sandbox.listCommands` | `ListCommands` |
| `sandbox.getCommand` | `GetCommand`, then one `Attach` on the node carrying output and stdin |
| `child.kill` | `SignalCommand` |
| `sandbox.pruneCommands` | `PruneCommands` |
| `sandbox.createUser`, `createGroup` | `CreateUser`, `CreateGroup` |
| `sandbox.addUserToGroup`, `removeUserFromGroup` | `AddUserToGroup`, `RemoveUserFromGroup` |
| `fs.readFile`, as root with the default flag | `DownloadFile` on the node |
| `fs.readFile` otherwise, `writeFile`, `appendFile` | `Fs` on the node: open, a read or write per 4 MiB, close |
| `fs.stat`, `lstat`, `readdir`, `mkdir`, `mkdtemp`, `rm`, `rmdir`, `unlink`, `rename`, `copyFile`, `cp`, `chmod`, `chown`, `lchown`, `utimes`, `lutimes`, `truncate`, `symlink`, `link`, `readlink`, `realpath`, `access` | `Fs` on the node, one call each (`cp` without `force`, or with a `filter`, one per entry) |
| `fs.open`, and every `FileHandle` method | `Fs` on the node, one call each |
| `fs.watch` | `Watch` on the node |
| `sandbox.exposePort`, `listPorts`, `closePort`, `domain` | `ExposePort`, `ListPorts`, `ClosePort` |
| `sandbox.updateTags` | `UpdateTags` |
| `sandbox.updateNetworkPolicy` | `UpdateNetworkPolicy` |
| `sandbox.updateResources` | `UpdateResources` |
| `sandbox.updateAccessPolicy` | `UpdateAccessPolicy` |
| `sandbox.listSessions`, `currentSession` | `ListSessions` |
| `sandbox.stop` | `PauseSandbox` |
| `sandbox.resume` | `ResumeSandbox` |
| `sandbox.shutdown` | `StopSandbox` |
| `sandbox.boot` | `StartSandbox` |
| `sandbox.recreate` | `RecreateSandbox` |
| `sandbox.delete` | `DeleteSandbox` |
| `sandbox.snapshot`, `Snapshot.list`, `get`, `delete` | `CreateSnapshot`, `ListSnapshots`, `GetSnapshot`, `DeleteSnapshot` |
| `Template.build`, `list`, `delete` | `BuildTemplate`, `ListTemplates`, `DeleteTemplate` |
| `burrow.audit` | `QueryAudit` |
| `burrow.events` | `TailEvents` |
| `burrow.nodes`, `drainNode` | `ListNodes`, `DrainNode` |
| `burrow.setSecret`, `listSecrets`, `deleteSecret` | `SetSecret`, `ListSecrets`, `DeleteSecret` |
| `burrow.health` | `Health` |

## Migrating from earlier versions

Each operation now has one name. File and command calls are Node's own
`fs/promises` and `child_process`, under `sandbox.fs` and
`sandbox.childProcess`, and the network shorthands are gone in favour of the
one policy object. What was removed, and what to use instead:

| Gone | Use |
|---|---|
| `sandbox.exec(cmd)`, `sandbox.exec([file, ...args])` | `childProcess.exec(cmd)`, `childProcess.execFile(file, args)` |
| `exec(..., { check: true })`, `CommandFailedError` | `exec` and `execFile` reject on any failure, with Node's error |
| `sandbox.spawn`, `execStream`, `logs()`, `wait()` | `childProcess.spawn`, its `stdout`/`stderr` streams, and its `close` event |
| `command.kill(9)`, `sendStdin`, `closeStdin` | `child.kill("SIGKILL")`, `child.stdin.write`, `child.stdin.end()` |
| `getCommand(id).info`, `logs()` | `listCommands()` for the record; `getCommand(id)` is now a `ChildProcess` |
| `onStdout`, `onStderr` | `child.stdout.on("data")`, `child.stderr.on("data")` |
| `sandbox.readFile(path)`, `readFileBytes`, `openFile` | `fs.readFile(path, "utf8")`, `fs.readFile(path)`, `fs.open(path)` and `createReadStream` |
| `sandbox.writeFile`, `writeFiles` | `fs.writeFile`, once per file; `fs.mkdir(dir, { recursive: true })` first, since parents are no longer made |
| `sandbox.downloadFile(src, dst)` | `pipeline((await fs.open(src)).createReadStream(), createWriteStream(dst))` |
| `sandbox.listDir`, `mkdir`, `remove`, `rename` | `fs.readdir(path, { withFileTypes: true })`, `fs.mkdir`, `fs.rm(path, { recursive: true, force: true })`, `fs.rename` |
| `sandbox.stat(path)` returning `null`, `exists` | `fs.stat`, which throws `ENOENT`; `fs.access` |
| `sandbox.watch(path, { onEvent })`, `watcher.stop()` | `for await (... of fs.watch(path, { signal }))`, and abort the signal |
| `networkPolicy: "allow-all"`, `"deny-all"` | `"open"`, `"none"` |
| `networkPolicy: { allow, subnets }` | `{ mode: "allowlist", allowDomains, allowCidrs, denyCidrs }` |
| `allow: { domain: { transform, match } }`, `forwardURL`, `forwardSecret` | `rules: [{ domain, match, setHeaders }]`, `forward: { url, secret }`, with `inspectTls: true` |
| `sandbox.commands`, `sandbox.pty` | `childProcess`, and `terminal()` |
| `Sandbox.connect(id)`, `Sandbox.fork({ source })` | `Sandbox.get({ id })`, `(await Sandbox.get({ id })).fork()` |
| `update({...})`, `extendTimeout`, `setTimeout` | `updateTags`, `updateNetworkPolicy`, `updateAccessPolicy`, `updateResources` |
| `pause`, `kill` | `stop`, `delete` |
| `getInfo`, `isRunning` | `refresh()`, then `state` |
| `status`, `image`, `metadata`, `memory`, `sandboxId`, `networkPolicy` | `state`, `template`, `tags`, `memoryMib`, `id`, `policy.network` |
| `burrow.create`, `get`, `list` | `Sandbox.create`, `get`, `list` |
| `network`, `image`, `metadata` options | `networkPolicy`, `template`, `tags` |

`sandbox.checkpoint()` is gone. Memory written without the disk is not a restore
point, and the guest keeps writing to its disk the moment it resumes, so the two
halves stop agreeing. Use `sandbox.snapshot()`, which copies both, or
`sandbox.fork()`, which does the same into a new sandbox. Both still write the
source's state without stopping it.

## Development

```sh
npm install
npm run build        # syncs protos from the workspace, then compiles
npm run typecheck
node examples/quickstart.mjs   # needs a running burrow stack
```
