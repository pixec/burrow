import { Buffer } from "node:buffer";
import type { Abortable } from "node:events";
import type {
  BufferEncodingOption,
  CopyOptions,
  EncodingOption,
  MakeDirectoryOptions,
  Mode,
  ObjectEncodingOptions,
  OpenMode,
  PathLike,
  RmDirOptions,
  RmOptions,
  StatOptions,
  TimeLike,
} from "node:fs";
import type { FileChangeInfo } from "node:fs/promises";
import { posix } from "node:path";

import {
  attach,
  collect,
  startCommand,
  type ChildProcess,
  type ExecCommandOptions,
  type ExecFileOptions,
  type PromiseWithChild,
  type SpawnOptions,
} from "./child-process.js";
import { withClient, withConnection } from "./client.js";
import { BurrowError } from "./errors.js";
import {
  abortError,
  constants,
  Dirent,
  encoded,
  FileHandle,
  fsError,
  fsRequest,
  optionsOf,
  Stats,
  toFlags,
  toMode,
  toNanos,
  toPath,
  typeOf,
  type Encoding,
  type ReadFileOptions,
  type WatchOptions,
  type WriteData,
  type WriteFileOptions,
} from "./fs.js";
import type { GuestLink } from "./guest.js";
import { toPublicIp } from "./ip.js";
import {
  fromPolicy,
  resolveNetwork,
  toExecPolicy,
  toFsPolicy,
  toKitSpec,
  toLifetimePolicy,
  toNetworkPolicy,
  toNetworks,
  toResourcePolicy,
  toSnapshotPolicy,
  toVolumeMounts,
} from "./policy.js";
import { Snapshot, type SnapshotOptions } from "./snapshot.js";
import { Terminal, type TerminalOptions } from "./terminal.js";
import type { ConnectionOptions, Transport, TransportOptions } from "./transport.js";
import type {
  CheckpointKind,
  CallOptions,
  CommandInfo,
  CommandState,
  CreateOptions,
  ExposePortOptions,
  ForkOptions,
  GetCommandOptions,
  GetOptions,
  GetOrCreateOptions,
  GuestGroup,
  GuestUser,
  HandleOptions,
  ListOptions,
  MoveOptions,
  NetworkInput,
  PasswordSet,
  PortMapping,
  PublicIp,
  RecreateOptions,
  RemoteDesktopCredential,
  ResourceChange,
  ResourceOutcome,
  ResourcesUpdate,
  ResourceUpdateOptions,
  SandboxInfo,
  SandboxState,
  Session,
  SessionEnd,
  SessionStart,
  Share,
  ShareOptions,
  StartOptions,
  UpdateAccessOptions,
  UpdateLifetimeOptions,
  Usage,
  WindowsActivation,
} from "./types.js";
import { dateOf, dateOrNull, enumOf, toKernelInfo } from "./wire.js";

const STATES: readonly SandboxState[] = [
  "creating",
  "running",
  "suspended",
  "stopped",
  "destroyed",
  "failed",
];
const SESSION_STARTS: readonly SessionStart[] = ["boot", "restore", "resume"];
const SESSION_ENDS: readonly SessionEnd[] = [
  "suspended",
  "deleted",
  "failed",
  "stopped",
  "guest_exited",
  "crashed",
];
const COMMAND_STATES: readonly CommandState[] = ["running", "exited"];
const RESOURCE_CHANGES: readonly ResourceChange[] = [
  "unchanged",
  "live",
  "partial",
  "next_boot",
  "offline",
  "refused",
];

/** @internal One `Sandbox` record as the SDK reports it. */
export function toSandboxInfo(raw: any): SandboxInfo {
  return {
    id: raw.id,
    name: raw.name ?? "",
    nodeId: raw.nodeId ?? "",
    template: raw.template ?? "",
    buildDigest: raw.buildDigest ?? "",
    state: Sandbox.stateOf(raw.state),
    createdAt: dateOf(raw.createdAtUnixMs),
    guestIp: raw.guestIp ?? "",
    tags: raw.tags ?? {},
    policy: fromPolicy(raw.policy),
    unreachable: raw.isUnreachable ?? false,
    usage: {
      // 64-bit on the wire, but nothing a sandbox consumes reaches the range
      // where handing them over as numbers costs precision.
      cpuUsageUsec: Number(raw.cpuUsageUsec ?? 0),
      rxBytes: Number(raw.rxBytes ?? 0),
      txBytes: Number(raw.txBytes ?? 0),
    },
    durable: raw.isDurable ?? false,
    hypervisor: raw.hypervisor ?? "",
    hypervisorVersion: raw.hypervisorVersion ?? "",
    kernel: toKernelInfo(raw.kernel),
    guestOs: raw.guestOs ?? "",
    publicIps: (raw.publicIps ?? []).map(toPublicIp),
    checkpointAt: dateOrNull(raw.checkpointAtUnixMs),
    checkpointKind: Number(raw.checkpointAtUnixMs ?? 0) > 0 ? checkpointKindOf(raw.checkpointKind) : null,
    remoteDesktop: raw.remoteDesktop
      ? {
          username: raw.remoteDesktop.username ?? "",
          password: raw.remoteDesktop.password ?? "",
          port: Number(raw.remoteDesktop.port ?? 0),
        }
      : null,
    activation: raw.activation
      ? {
          kmsHost: raw.activation.kmsHost ?? "",
          productKeyInstalled: raw.activation.isProductKeyInstalled ?? false,
          activated: raw.activation.isActivated ?? false,
          status: raw.activation.status ?? "",
          checkedAt: dateOrNull(raw.activation.checkedAtUnixMs),
        }
      : null,
  };
}

function checkpointKindOf(raw: unknown): CheckpointKind {
  return raw === "CHECKPOINT_KIND_MEMORY" ? "memory" : "disk";
}

function toResourceOutcome(raw: any): ResourceOutcome | undefined {
  if (!raw) return undefined;
  return {
    change: enumOf(raw.change, "RESOURCE_CHANGE_", RESOURCE_CHANGES),
    previous: raw.previous ?? 0,
    value: raw.value ?? 0,
    reason: raw.reason ?? "",
  };
}

/** @internal What an `UpdateResources` answer says, field by field. */
export function toResourcesUpdate(raw: any): ResourcesUpdate {
  const update: ResourcesUpdate = { filesystemBytes: Number(raw.filesystemBytes ?? 0) };
  const fields = [
    ["vcpus", raw.vcpus],
    ["memoryMib", raw.memMib],
    ["diskMib", raw.diskMib],
  ] as const;
  for (const [name, field] of fields) {
    const outcome = toResourceOutcome(field);
    if (outcome) update[name] = outcome;
  }
  if (raw.limits) {
    update.limits = {
      change: enumOf(raw.limits.change, "RESOURCE_CHANGE_", RESOURCE_CHANGES),
      reason: raw.limits.reason ?? "",
    };
  }
  return update;
}

function toSession(raw: any): Session {
  const endedBy = enumOf(raw.endedBy, "SESSION_END_", SESSION_ENDS);
  return {
    id: raw.id ?? "",
    sandboxId: raw.sandboxId ?? "",
    startedAt: dateOf(raw.startedAtUnixMs),
    endedAt: dateOrNull(raw.endedAtUnixMs),
    startedBy: enumOf(raw.startedBy, "SESSION_START_", SESSION_STARTS),
    endedBy:
      // Unspecified is an open session; the node's own "unknown" is a session
      // it lost track of, which reads as such.
      String(raw.endedBy ?? "SESSION_END_UNSPECIFIED") === "SESSION_END_UNSPECIFIED"
        ? null
        : endedBy,
  };
}

/** Turns a guest's report of one command into the SDK's shape. */
function toCommandInfo(raw: any): CommandInfo {
  return {
    cmdId: raw.commandId ?? "",
    cmd: raw.cmd ?? [],
    user: raw.user ?? "",
    state: enumOf(raw.state, "COMMAND_STATE_", COMMAND_STATES),
    exitCode: Number(raw.exitCode ?? 0),
    startedAt: dateOf(raw.startedAtUnixMs),
    endedAt: dateOrNull(raw.endedAtUnixMs),
    bufferedBytes: Number(raw.bufferedBytes ?? 0),
    exitSignal: Number(raw.exitSignal ?? 0),
    outputBytes: Number(raw.outputBytes ?? 0),
  };
}

function toShare(raw: any): Share {
  return {
    address: raw.address ?? "",
    ports: (raw.ports ?? []).map((p: any) => Number(p)),
    allowedClients: raw.allowedClients ?? [],
    createdAt: dateOf(raw.createdAtUnixMs),
    udpPorts: (raw.udpPorts ?? []).map((p: any) => Number(p)),
    allUdp: Boolean(raw.isAllUdp),
    transparentIp: Boolean(raw.isTransparentIp),
  };
}

function toPort(raw: any, fallbackHost: string): PortMapping {
  const hostPort = Number(raw.hostPort ?? 0);
  // The node advertises where it accepts traffic; when it has not, the control
  // plane's own host is the best guess, and the right one for a single node.
  const address = raw.hostAddress || `${fallbackHost}:${hostPort}`;
  return {
    guestPort: Number(raw.guestPort ?? 0),
    hostPort,
    udp: Boolean(raw.isUdp),
    url: `http://${address}`,
    // Empty unless the holding node's edge is serving, rather than a name
    // that resolves nowhere.
    edgeUrl: raw.edgeUrl || undefined,
  };
}

/**
 * A sandbox.
 *
 * Obtained from {@link Sandbox.create}, {@link Sandbox.get}, a {@link Burrow}
 * client's `sandboxes`, or {@link Sandbox.fork}; not constructed directly.
 *
 * Besides its lifecycle, a handle carries the guest's files and commands as
 * Node's `fs/promises` and `child_process` functions:
 *
 * ```ts
 * await sandbox.mkdir("/work/src", { recursive: true });
 * await sandbox.writeFile("/work/src/app.py", "print('hi')\n");
 * const { stdout } = await sandbox.execFile("python3", ["/work/src/app.py"]);
 * ```
 */
export class Sandbox {
  readonly id: string;
  private info: SandboxInfo;
  private readonly transport: Transport;
  private readonly owned: boolean;
  /** Resume a suspended sandbox and retry once, rather than failing the call. */
  autoResume: boolean;
  /**
   * Environment merged under every command this handle runs.
   *
   * Client-side, because the server has nowhere to keep it: a handle obtained
   * elsewhere does not have these, and the sandbox itself never learns them.
   */
  readonly env: Record<string, string>;
  /**
   * Guest user every command from this handle runs as. Empty is root.
   *
   * Set only on a handle from {@link asUser}; a per-command `user` still wins.
   */
  private defaultUser = "";
  /** Called after this handle resumes the sandbox, including auto-resume. */
  private readonly onResume?: (sandbox: Sandbox) => void | Promise<void>;
  /** Set by {@link delete}: a destroyed sandbox has nothing left to call. */
  private destroyed = false;
  /** What the file and command methods reach the sandbox through, read live. */
  private readonly guest: GuestLink;

  /**
   * @internal A handle on `transport`. An owned handle holds one share of
   * the connection and releases it on `close`; one from {@link asUser} rides
   * on its parent's.
   */
  constructor(transport: Transport, info: SandboxInfo, options: HandleOptions = {}, owned = true) {
    this.transport = transport;
    this.info = info;
    this.id = info.id;
    this.owned = owned;
    this.autoResume = options.autoResume ?? true;
    this.env = options.env ?? {};
    this.onResume = options.onResume;
    const sandbox = this;
    this.guest = {
      sandboxId: this.id,
      get user() {
        return sandbox.defaultUser;
      },
      get env() {
        return sandbox.env;
      },
      get autoResume() {
        return sandbox.autoResume;
      },
      node: () => {
        this.assertLive();
        return this.node();
      },
      run: (op) => {
        this.assertLive();
        return this.withResume(op);
      },
      resume: () => this.resume(),
      signalCommand: (cmdId, signal) => this.killCommand(cmdId, signal),
    };
  }

  /** @internal The SDK's name for a wire `SandboxState`. */
  static stateOf(state: unknown): SandboxState {
    return enumOf(state, "SANDBOX_STATE_", STATES);
  }

  /** @internal Builds a `CreateSandboxRequest`. */
  static createRequest(options: CreateOptions): any {
    // A snapshot carries its own template, and one that disagrees is an error,
    // so nothing is sent as if the caller had asked for it.
    const template = options.template ?? "";
    // Without a snapshot there is nothing to boot from, and a made-up "default"
    // would turn a missing argument into a not_found for a template nobody
    // named.
    if (!template && !options.snapshot) {
      throw new BurrowError(
        "a template is required: pass `template` (or `snapshot` to restore one)",
        "invalid_argument",
      );
    }
    return {
      name: options.name ?? "",
      requestId: options.requestId ?? "",
      snapshot: options.snapshot ?? "",
      template,
      policy: {
        resources: toResourcePolicy(options.resources),
        lifetime: toLifetimePolicy(options.lifetime),
        snapshots: toSnapshotPolicy(options.snapshots),
        // Left off the request entirely unless the caller asked for a limit:
        // absent is what the node reads as "allowed".
        exec: toExecPolicy(options.exec),
        fs: toFsPolicy(options.fs),
        network: toNetworkPolicy(resolveNetwork(options.networkPolicy)),
        networks: toNetworks(options.networks, options.alias),
        volumes: toVolumeMounts(options.volumes),
        isConsoleVerbose: options.verboseConsole ?? false,
      },
      tags: options.tags ?? {},
      nodeLabels: options.nodeLabels ?? {},
      kit: toKitSpec(options.kit),
      publicIps: options.publicIps ?? [],
      isRemoteDesktopEnabled: options.remoteDesktop ?? false,
      activation: options.activation
        ? {
            productKeySecret: options.activation.productKeySecret ?? "",
            kmsHost: options.activation.kmsHost ?? "",
          }
        : undefined,
    };
  }

  /**
   * Creates a sandbox and waits for it to be ready to accept commands.
   *
   * Opens a connection for this one sandbox; a {@link Burrow} client shares
   * one across many. `timeoutMs` is the wait for the boot, 120 seconds by
   * default, and `callTimeoutMs` the default deadline of every later call on
   * the handle.
   */
  static create(options: CreateOptions & ConnectionOptions = {}): Promise<Sandbox> {
    return withConnection(options, (burrow) => burrow.sandboxes.create(options));
  }

  /**
   * Returns the sandbox with this name, creating it if it is not there.
   *
   * ```ts
   * const sandbox = await Sandbox.getOrCreate({
   *   name: "build-482",
   *   template: "python-tools",
   *   onCreate: (s) => s.writeFile("/work/app.py", src),
   * });
   * ```
   */
  static getOrCreate(options: GetOrCreateOptions & ConnectionOptions = {}): Promise<Sandbox> {
    return withConnection(options, (burrow) => burrow.sandboxes.getOrCreate(options));
  }

  /**
   * Returns a handle for a sandbox that already exists, by id or name.
   *
   * ```ts
   * const sandbox = await Sandbox.get("build-482");
   * ```
   */
  static get(options: (GetOptions & TransportOptions) | string): Promise<Sandbox> {
    const params = typeof options === "string" ? { id: options } : options;
    return withClient(params, (burrow) => burrow.sandboxes.get(params));
  }

  /**
   * Lists sandboxes, newest state first, as an async iterable of handles.
   *
   * ```ts
   * for await (const sandbox of Sandbox.list({ tag: "owner=ci" })) {
   *   await sandbox.pause();
   * }
   * ```
   */
  static list(
    options: ListOptions & TransportOptions = {},
  ): AsyncIterable<Sandbox> & { toArray(): Promise<Sandbox[]> } {
    const iterate = async function* (): AsyncGenerator<Sandbox> {
      yield* await withClient(options, async (burrow) => {
        const handles: Sandbox[] = [];
        for await (const sandbox of burrow.sandboxes.list(options)) handles.push(sandbox);
        return handles;
      });
    };
    return {
      [Symbol.asyncIterator]: iterate,
      async toArray() {
        const all: Sandbox[] = [];
        for await (const sandbox of iterate()) all.push(sandbox);
        return all;
      },
    };
  }

  /**
   * Refuses a call on a deleted sandbox. `delete` released the connection, so
   * the alternative is an obscure transport failure some calls later.
   */
  private assertLive(): void {
    if (this.destroyed) {
      throw new BurrowError(`sandbox ${this.id} was deleted`, "failed_precondition");
    }
  }

  /**
   * The name the sandbox was created with, falling back to its id when it was
   * created without one. Both work anywhere the API takes a sandbox.
   */
  get name(): string {
    return this.info.name || this.id;
  }

  get state(): SandboxState {
    return this.info.state;
  }

  get template(): string {
    return this.info.template;
  }

  /** Node hosting the sandbox. */
  get nodeId(): string {
    return this.info.nodeId;
  }

  /** Address the sandbox holds on the networks it joined. */
  get guestIp(): string {
    return this.info.guestIp;
  }

  /**
   * Whether the node hosting this sandbox has missed its heartbeats. When
   * true, `state` is a stale reading and calls fail with `unavailable` until
   * it returns. `delete()` still works: the orchestrator drops the sandbox on
   * its own word and destroys it if the node comes back.
   */
  get unreachable(): boolean {
    return this.info.unreachable;
  }

  /**
   * Suspended with its latest suspend in the object store, so it can resume
   * on another node.
   */
  get durable(): boolean {
    return this.info.durable;
  }

  /**
   * The Remote Desktop logon a create with `remoteDesktop` made. Only the
   * handle that create returned has it; nothing shows it again.
   */
  get remoteDesktop(): RemoteDesktopCredential | null {
    return this.info.remoteDesktop;
  }

  /** How a Windows guest created with an activation activates. */
  get activation(): WindowsActivation | null {
    return this.info.activation;
  }

  /** Tags, as of the last call that returned the sandbox record. */
  get tags(): Record<string, string> {
    return this.info.tags;
  }

  get vcpus(): number {
    return this.info.policy.resources.vcpus;
  }

  get memoryMib(): number {
    return this.info.policy.resources.memoryMib;
  }

  /** How far {@link updateResources} can grow the memory while it runs. */
  get maxMemoryMib(): number {
    return this.info.policy.resources.maxMemoryMib;
  }

  /**
   * What the sandbox has consumed, as of the last call that returned its
   * record; {@link refresh} for a current reading. Accumulated across every VM
   * it has run, so a pause and a resume do not reset it.
   */
  get usage(): Usage {
    return this.info.usage;
  }

  /** There is no `updatedAt`: the record does not carry one. */
  get createdAt(): Date {
    return this.info.createdAt;
  }

  /** The whole policy in force, with injected header values redacted. */
  get policy(): SandboxInfo["policy"] {
    return this.info.policy;
  }

  /** Re-reads the sandbox's current state from the server. */
  refresh(options: CallOptions = {}): Promise<SandboxInfo> {
    return this.mutate("GetSandbox", { sandboxId: this.id }, options);
  }

  /**
   * One call that returns the sandbox's record: the record replaces what the
   * handle holds, so every getter reads what the server last said.
   */
  private async mutate(
    method: string,
    request: object,
    options: CallOptions,
    timeoutMs?: number,
  ): Promise<SandboxInfo> {
    this.assertLive();
    const raw = await this.transport.unary<any, any>(
      method,
      request,
      options.timeoutMs ?? timeoutMs,
      options.signal,
    );
    this.info = toSandboxInfo(raw);
    return this.info;
  }

  /** A unary call to the control plane about this sandbox. */
  private call<Res>(method: string, request: object, options: CallOptions): Promise<Res> {
    this.assertLive();
    return this.transport.unary<any, Res>(method, request, options.timeoutMs, options.signal);
  }

  /**
   * Runs `op`, resuming the sandbox and retrying once if it is suspended.
   *
   * The daemon answers a call that needs a live guest with
   * `FAILED_PRECONDITION: sandbox is suspended; resume it first`, and nothing
   * else in the API reports that, so it is specific enough to act on.
   */
  private async withResume<T>(op: () => Promise<T>, enabled = this.autoResume): Promise<T> {
    try {
      return await op();
    } catch (err) {
      if (!enabled || !(err instanceof BurrowError) || !err.isSuspended) throw err;
      await this.resume();
      return await op();
    }
  }

  /**
   * Lists the commands this sandbox has run, oldest first.
   *
   * ```ts
   * for (const command of await sandbox.listCommands()) {
   *   console.log(command.cmdId, command.state, command.cmd.join(" "));
   * }
   * ```
   */
  async listCommands(options: CallOptions = {}): Promise<CommandInfo[]> {
    const res = await this.call<any>("ListCommands", { sandboxId: this.id }, options);
    return (res.commands ?? []).map(toCommandInfo);
  }

  /**
   * Reaches a command by id, from anywhere, as a {@link ChildProcess}.
   *
   * ```ts
   * const child = await sandbox.getCommand(cmdId);
   * child.stdout.pipe(process.stdout);
   * child.stdin.write("more input\n");
   * ```
   *
   * The command need not have been started by this process: it lives in the
   * sandbox, and so does every byte it has printed. Its output is replayed
   * from `fromOffset`, counting stdout and stderr bytes together from the
   * command's start, and then followed live; a reader that saw N bytes
   * passes N and gets only what came after. `stdin` feeds the running
   * command, a shell whose original stream is long gone included, and
   * `kill()` signals it. Several readers may follow one command at once.
   * Throws `not_found` when the id names nothing, a pruned command included.
   */
  async getCommand(cmdId: string, options: GetCommandOptions = {}): Promise<ChildProcess> {
    // Read first, so a bad id fails here rather than as an `error` event.
    const raw = await this.call<any>(
      "GetCommand",
      { sandboxId: this.id, commandId: cmdId },
      options,
    );
    return attach(this.guest, cmdId, options.fromOffset ?? 0, toCommandInfo(raw).cmd);
  }

  /**
   * Removes finished commands and their output, as `docker container prune`
   * does. Running commands are left alone.
   */
  async pruneCommands(options: CallOptions = {}): Promise<{ removed: number; freedBytes: number }> {
    const res = await this.call<any>("PruneCommands", { sandboxId: this.id }, options);
    return {
      removed: Number(res.removed ?? 0),
      freedBytes: Number(res.freedBytes ?? 0),
    };
  }

  // Commands, as Node's `child_process`: `spawn`, `exec` and `execFile`.
  // Each runs as the handle's user, with the handle's `env` under its own.
  // Only the asynchronous API: a sync call would block this process on the
  // network.

  /**
   * Starts `command` with `args`, as Node's `spawn`: without `shell` the
   * command is the program and no shell is involved, so `args` need no
   * quoting. `argv0` is not offered, since the guest runs `argv` as given.
   */
  spawn(command: string, options?: SpawnOptions): ChildProcess;
  spawn(command: string, args: readonly string[], options?: SpawnOptions): ChildProcess;
  spawn(
    command: string,
    argsOrOptions?: readonly string[] | SpawnOptions,
    maybeOptions?: SpawnOptions,
  ): ChildProcess {
    const args = Array.isArray(argsOrOptions) ? [...argsOrOptions] : [];
    const options: SpawnOptions =
      (Array.isArray(argsOrOptions) ? maybeOptions : (argsOrOptions as SpawnOptions | undefined)) ?? {};
    return startCommand(this.guest, command, args, options);
  }

  /**
   * Runs `command` through a shell and resolves `{ stdout, stderr }` once it
   * exits 0, as `util.promisify(exec)`. Otherwise rejects with Node's error:
   * `code` the exit code (null after a signal), `signal`, `killed`, `cmd`,
   * and the output so far.
   */
  exec(
    command: string,
    options?: ExecCommandOptions & { encoding?: BufferEncoding },
  ): PromiseWithChild<{ stdout: string; stderr: string }>;
  exec(
    command: string,
    options: ExecCommandOptions & { encoding: "buffer" | null },
  ): PromiseWithChild<{ stdout: Buffer; stderr: Buffer }>;
  exec(
    command: string,
    options?: ExecCommandOptions,
  ): PromiseWithChild<{ stdout: string | Buffer; stderr: string | Buffer }>;
  exec(
    command: string,
    options: ExecCommandOptions = {},
  ): PromiseWithChild<{ stdout: string | Buffer; stderr: string | Buffer }> {
    return collect(this.spawn(command, { ...options, shell: options.shell ?? true }), command, options);
  }

  /** Runs `file` with `args`, no shell, as `util.promisify(execFile)`. Settles as {@link exec}. */
  execFile(
    file: string,
    options?: ExecFileOptions & { encoding?: BufferEncoding },
  ): PromiseWithChild<{ stdout: string; stderr: string }>;
  execFile(
    file: string,
    args: readonly string[] | null | undefined,
    options?: ExecFileOptions & { encoding?: BufferEncoding },
  ): PromiseWithChild<{ stdout: string; stderr: string }>;
  execFile(
    file: string,
    args: readonly string[] | null | undefined,
    options: ExecFileOptions & { encoding: "buffer" | null },
  ): PromiseWithChild<{ stdout: Buffer; stderr: Buffer }>;
  execFile(
    file: string,
    args?: readonly string[] | null,
    options?: ExecFileOptions,
  ): PromiseWithChild<{ stdout: string | Buffer; stderr: string | Buffer }>;
  execFile(
    file: string,
    argsOrOptions?: readonly string[] | null | ExecFileOptions,
    maybeOptions?: ExecFileOptions,
  ): PromiseWithChild<{ stdout: string | Buffer; stderr: string | Buffer }> {
    const args = Array.isArray(argsOrOptions) ? [...argsOrOptions] : [];
    const options: ExecFileOptions =
      (Array.isArray(argsOrOptions) || argsOrOptions === null
        ? maybeOptions
        : (argsOrOptions as ExecFileOptions | undefined)) ?? {};
    return collect(this.spawn(file, args, options), [file, ...args].join(" "), options);
  }

  // Files, as Node's `fs/promises`: the same functions, signatures, defaults
  // and errors, performed by the guest kernel as the handle's user. Kernel
  // errors are Node's (`code`, negative `errno`, `syscall`, `path`). The file
  // policy refuses the way the kernel would: `EACCES` for a path or a
  // direction it does not allow, `EFBIG` past its write ceiling.

  async access(path: PathLike, mode: number = constants.F_OK): Promise<void> {
    await fsRequest(this.guest, "access", { path: toPath(path), mode });
  }

  /** {@link writeFile} with `flag` defaulting to `"a"`. */
  async appendFile(
    path: PathLike | FileHandle,
    data: WriteData,
    options?: WriteFileOptions | BufferEncoding | null,
  ): Promise<void> {
    const opts = optionsOf(options);
    await this.writeWhole(path, data, { ...opts, flag: opts.flag ?? "a" });
  }

  async chmod(path: PathLike, mode: Mode): Promise<void> {
    await fsRequest(this.guest, "chmod", { path: toPath(path), mode: toMode(mode, 0) });
  }

  async chown(path: PathLike, uid: number, gid: number): Promise<void> {
    await fsRequest(this.guest, "chown", { path: toPath(path), uid, gid, isNofollow: false });
  }

  /**
   * Copies one file. `COPYFILE_EXCL` fails with `EEXIST` rather than
   * replacing; `COPYFILE_FICLONE` is a hint and ignored. The agent cannot
   * promise a copy-on-write clone, so `COPYFILE_FICLONE_FORCE` fails with
   * `ENOSYS`, as Node's does on a filesystem without one.
   */
  async copyFile(src: PathLike, dest: PathLike, mode = 0): Promise<void> {
    if (mode & constants.COPYFILE_FICLONE_FORCE) {
      throw fsError({ code: "ENOSYS", errno: 38, syscall: "copyfile", path: toPath(src), dest: toPath(dest) });
    }
    await fsRequest(this.guest, "copy", {
      src: toPath(src),
      dst: toPath(dest),
      isExclusive: (mode & constants.COPYFILE_EXCL) !== 0,
      isRecursive: false,
      isPreserving: false,
    });
  }

  /**
   * Copies a file or, with `recursive`, a tree. One call does it unless
   * existing files are to be skipped (`force: false` without `errorOnExist`)
   * or a `filter` is given; those walk the tree from here, a call per entry.
   * `preserveTimestamps` carries the mode over as well as the times.
   * `dereference` and `verbatimSymlinks` are not offered: links are copied
   * as links.
   */
  async cp(source: string | URL, destination: string | URL, options: CopyOptions = {}): Promise<void> {
    const src = toPath(source);
    const dst = toPath(destination);
    const force = options.force ?? true;
    const errorOnExist = options.errorOnExist ?? false;
    const copy = (from: string, to: string, isRecursive: boolean) =>
      fsRequest(this.guest, "copy", {
        src: from,
        dst: to,
        isExclusive: !force,
        isRecursive,
        isPreserving: options.preserveTimestamps ?? false,
      });

    if (!options.filter && (force || errorOnExist)) {
      await copy(src, dst, options.recursive ?? false);
      return;
    }

    const walk = async (from: string, to: string): Promise<void> => {
      if (options.filter && !(await options.filter(from, to))) return;
      const stats = await this.lstat(from);
      if (!stats.isDirectory()) {
        try {
          await copy(from, to, false);
        } catch (err) {
          if (!force && !errorOnExist && (err as NodeJS.ErrnoException).code === "EEXIST") return;
          throw err;
        }
        return;
      }
      if (!options.recursive) {
        throw fsError({ code: "EISDIR", errno: 21, syscall: "cp", path: from });
      }
      await this.mkdir(to, { recursive: true });
      for (const name of await this.readdir(from)) {
        await walk(posix.join(from, name), posix.join(to, name));
      }
    };
    await walk(src, dst);
  }

  async lchown(path: PathLike, uid: number, gid: number): Promise<void> {
    await fsRequest(this.guest, "chown", { path: toPath(path), uid, gid, isNofollow: true });
  }

  async link(existingPath: PathLike, newPath: PathLike): Promise<void> {
    await fsRequest(this.guest, "link", { existing: toPath(existingPath), path: toPath(newPath) });
  }

  async lstat(path: PathLike, _options?: StatOptions & { bigint?: false }): Promise<Stats> {
    return new Stats(await fsRequest(this.guest, "stat", { path: toPath(path), isNofollow: true }));
  }

  async lutimes(path: PathLike, atime: TimeLike, mtime: TimeLike): Promise<void> {
    await fsRequest(this.guest, "utimes", {
      path: toPath(path),
      atimeNs: toNanos(atime),
      mtimeNs: toNanos(mtime),
      isNofollow: true,
    });
  }

  /**
   * Creates a directory. With `recursive`, missing parents too, and resolves
   * with the first directory it created, or `undefined` when it created none.
   */
  mkdir(
    path: PathLike,
    options: MakeDirectoryOptions & { recursive: true },
  ): Promise<string | undefined>;
  mkdir(
    path: PathLike,
    options?: Mode | (MakeDirectoryOptions & { recursive?: false }) | null,
  ): Promise<void>;
  mkdir(path: PathLike, options?: Mode | MakeDirectoryOptions | null): Promise<string | undefined>;
  async mkdir(
    path: PathLike,
    options?: Mode | MakeDirectoryOptions | null,
  ): Promise<string | void> {
    const opts: MakeDirectoryOptions =
      typeof options === "object" && options !== null ? options : { mode: options ?? undefined };
    const created: string | undefined = await fsRequest(this.guest, "mkdir", {
      path: toPath(path),
      mode: toMode(opts.mode, 0o777),
      isRecursive: opts.recursive ?? false,
    });
    return opts.recursive ? created || undefined : undefined;
  }

  /** Creates a unique directory by appending six random characters to `prefix`. */
  mkdtemp(prefix: string, options?: EncodingOption): Promise<string>;
  mkdtemp(prefix: string, options: BufferEncodingOption): Promise<Buffer>;
  async mkdtemp(
    prefix: string,
    options?: EncodingOption | BufferEncodingOption,
  ): Promise<string | Buffer> {
    return encoded(await fsRequest(this.guest, "mkdtemp", { prefix }), optionsOf(options).encoding);
  }

  /** Opens a file. Flags as Node's strings (`"r"`, `"w+"`, `"ax"`, ...) or Linux numbers. */
  async open(path: PathLike, flags?: OpenMode, mode?: Mode | null): Promise<FileHandle> {
    const resolved = toPath(path);
    const handle: number = await fsRequest(this.guest, "open", {
      path: resolved,
      flags: toFlags(flags, "r"),
      mode: toMode(mode, 0o666),
    });
    return new FileHandle(this.guest, handle, resolved);
  }

  /**
   * Lists a directory. `withFileTypes` returns {@link Dirent}s; `recursive`
   * descends, naming entries by their path below `path`. Where the guest
   * filesystem reports no d_type, the entry is stat'ed, as Node does.
   */
  readdir(
    path: PathLike,
    options?:
      | (ObjectEncodingOptions & { withFileTypes?: false; recursive?: boolean })
      | BufferEncoding
      | null,
  ): Promise<string[]>;
  readdir(
    path: PathLike,
    options: { encoding: "buffer"; withFileTypes?: false; recursive?: boolean } | "buffer",
  ): Promise<Buffer[]>;
  readdir(
    path: PathLike,
    options: ObjectEncodingOptions & { withFileTypes: true; recursive?: boolean },
  ): Promise<Dirent[]>;
  readdir(
    path: PathLike,
    options: { encoding: "buffer"; withFileTypes: true; recursive?: boolean },
  ): Promise<Dirent<Buffer>[]>;
  async readdir(
    path: PathLike,
    options?:
      | (Omit<ObjectEncodingOptions, "encoding"> & {
          encoding?: Encoding;
          withFileTypes?: boolean;
          recursive?: boolean;
        })
      | BufferEncoding
      | "buffer"
      | null,
  ): Promise<Array<string | Buffer | Dirent<string | Buffer>>> {
    const { encoding, withFileTypes, recursive } = optionsOf(options);
    const root = toPath(path);
    const out: Array<string | Buffer | Dirent<string | Buffer>> = [];
    // Breadth first, which is the order Node's recursive listing comes in.
    const queue = [""];
    for (let below = queue.shift(); below !== undefined; below = queue.shift()) {
      const dir = below ? posix.join(root, below) : root;
      const { entries } = await fsRequest(this.guest, "readDir", { path: dir });
      for (const entry of entries as Array<{ name: string; type: string }>) {
        let type = entry.type.replace("FILE_TYPE_", "").toLowerCase();
        if (type === "unspecified") type = typeOf(await this.lstat(posix.join(dir, entry.name)));
        const relative = below ? posix.join(below, entry.name) : entry.name;
        if (recursive && type === "dir") queue.push(relative);
        out.push(
          withFileTypes
            ? new Dirent(encoded(entry.name, encoding), dir, type)
            : encoded(relative, encoding),
        );
      }
    }
    return out;
  }

  /** Reads a whole file: an open, a read per 4 MiB, a close. */
  readFile(
    path: PathLike | FileHandle,
    options?: ({ encoding?: null; flag?: OpenMode } & Abortable) | null,
  ): Promise<Buffer>;
  readFile(
    path: PathLike | FileHandle,
    options: ({ encoding: BufferEncoding; flag?: OpenMode } & Abortable) | BufferEncoding,
  ): Promise<string>;
  readFile(
    path: PathLike | FileHandle,
    options?: ReadFileOptions | BufferEncoding | null,
  ): Promise<string | Buffer>;
  async readFile(
    path: PathLike | FileHandle,
    options?: ReadFileOptions | BufferEncoding | null,
  ): Promise<string | Buffer> {
    if (path instanceof FileHandle) return path.readFile(options);
    const { encoding, flag, signal } = optionsOf(options);
    const flags = toFlags(flag, "r");
    const handle = await this.open(toPath(path), flags);
    try {
      return await handle.readFile({ encoding: encoding ?? null, signal });
    } finally {
      await handle.close();
    }
  }

  readlink(path: PathLike, options?: EncodingOption): Promise<string>;
  readlink(path: PathLike, options: BufferEncodingOption): Promise<Buffer>;
  async readlink(
    path: PathLike,
    options?: EncodingOption | BufferEncodingOption,
  ): Promise<string | Buffer> {
    return encoded(await fsRequest(this.guest, "readlink", { path: toPath(path) }), optionsOf(options).encoding);
  }

  realpath(path: PathLike, options?: EncodingOption): Promise<string>;
  realpath(path: PathLike, options: BufferEncodingOption): Promise<Buffer>;
  async realpath(
    path: PathLike,
    options?: EncodingOption | BufferEncodingOption,
  ): Promise<string | Buffer> {
    return encoded(await fsRequest(this.guest, "realpath", { path: toPath(path) }), optionsOf(options).encoding);
  }

  async rename(oldPath: PathLike, newPath: PathLike): Promise<void> {
    await fsRequest(this.guest, "rename", { src: toPath(oldPath), dst: toPath(newPath) });
  }

  /**
   * Removes a file, or with `recursive` a tree; `force` makes a missing path
   * not an error. `maxRetries` and `retryDelay` are accepted and unused: the
   * busy-file errors they retry are Windows'.
   */
  async rm(path: PathLike, options: RmOptions = {}): Promise<void> {
    await fsRequest(this.guest, "remove", {
      path: toPath(path),
      isRecursive: options.recursive ?? false,
      isForce: options.force ?? false,
      isDirOnly: false,
    });
  }

  /** Removes an empty directory. Node's deprecated `recursive` acts as {@link rm}'s. */
  async rmdir(path: PathLike, options: RmDirOptions = {}): Promise<void> {
    await fsRequest(this.guest, "remove", {
      path: toPath(path),
      isRecursive: options.recursive ?? false,
      isForce: false,
      isDirOnly: !options.recursive,
    });
  }

  /** `bigint` is not offered: times arrive from the guest as doubles already. */
  async stat(path: PathLike, _options?: StatOptions & { bigint?: false }): Promise<Stats> {
    return new Stats(await fsRequest(this.guest, "stat", { path: toPath(path), isNofollow: false }));
  }

  /** `type` is Windows' and ignored, as Node ignores it elsewhere. */
  async symlink(target: PathLike, path: PathLike, _type?: string | null): Promise<void> {
    await fsRequest(this.guest, "symlink", { target: toPath(target), path: toPath(path) });
  }

  async truncate(path: PathLike, len = 0): Promise<void> {
    await fsRequest(this.guest, "truncate", { path: toPath(path), length: len });
  }

  async unlink(path: PathLike): Promise<void> {
    await fsRequest(this.guest, "remove", {
      path: toPath(path),
      isRecursive: false,
      isForce: false,
      isDirOnly: false,
    });
  }

  /** Times as a `Date`, seconds since the epoch, or a numeric string of them. */
  async utimes(path: PathLike, atime: TimeLike, mtime: TimeLike): Promise<void> {
    await fsRequest(this.guest, "utimes", {
      path: toPath(path),
      atimeNs: toNanos(atime),
      mtimeNs: toNanos(mtime),
      isNofollow: false,
    });
  }

  /**
   * Watches a directory, as Node's `fs/promises` `watch`: an async iterable
   * of `{ eventType, filename }`, `filename` relative to the directory.
   *
   * ```ts
   * const ac = new AbortController();
   * for await (const { eventType, filename } of sandbox.watch("/work", { signal: ac.signal })) {
   *   console.log(eventType, filename);
   * }
   * ```
   *
   * The guest polls rather than using inotify, so an edit is seen within
   * about `intervalMs`, and only directories can be watched. Aborting
   * `signal` ends the iteration with an `AbortError`, as Node's does.
   */
  async *watch(
    filename: PathLike,
    options: WatchOptions | BufferEncoding | "buffer" = {},
  ): AsyncGenerator<FileChangeInfo<string | Buffer>> {
    const { recursive, signal, encoding, intervalMs } = optionsOf<WatchOptions>(options);
    const root = toPath(filename);
    if (signal?.aborted) throw abortError(signal);
    try {
      for await (const raw of this.guest.node().serverStream<any, any>(
        "Watch",
        {
          sandboxId: this.guest.sandboxId,
          path: root,
          isRecursive: recursive ?? false,
          intervalMs: intervalMs ?? 0,
        },
        // A watch outlives any request deadline.
        Infinity,
        signal,
      )) {
        yield {
          // Node's two kinds: a name that appeared or went, and a change in place.
          eventType: raw.kind === "WATCH_EVENT_KIND_MODIFIED" ? "change" : "rename",
          filename: encoded(posix.relative(root, raw.path), encoding),
        };
      }
    } catch (err) {
      if (signal?.aborted) throw abortError(signal);
      throw err;
    }
  }

  /**
   * Writes a whole file, replacing it: `flag` `"w"`, `mode` 0o666 before the
   * umask. `data` may be a string, bytes, or an (async) iterable of either,
   * a `Readable` among them. Always opens and writes, never the upload
   * stream, which creates missing parents where Node fails with `ENOENT` and
   * cannot write as a user.
   */
  async writeFile(
    file: PathLike | FileHandle,
    data: WriteData,
    options?: WriteFileOptions | BufferEncoding | null,
  ): Promise<void> {
    await this.writeWhole(file, data, optionsOf(options));
  }

  private async writeWhole(
    file: PathLike | FileHandle,
    data: WriteData,
    options: Omit<Partial<WriteFileOptions>, "encoding"> & { encoding?: Encoding },
  ): Promise<void> {
    const { mode, flag, flush, signal } = options;
    const encoding = options.encoding === "buffer" ? null : options.encoding;
    if (file instanceof FileHandle) {
      await file.writeFile(data, { encoding, signal });
      return;
    }
    const handle = await this.open(file, toFlags(flag, "w"), mode);
    try {
      await handle.writeFile(data, { encoding, signal });
      if (flush) await handle.sync();
    } finally {
      await handle.close();
    }
  }

  /**
   * The way to this sandbox's exec, attach and file calls: its node, or the
   * orchestrator when the transport was opened with `route: "orchestrator"`.
   */
  private node() {
    return this.transport.route(this.id);
  }

  /**
   * Signals a command and resolves once the node has delivered it.
   *
   * Only one refusal is swallowed: the command had already exited, which is
   * what kill wanted anyway. Every other failure rejects, because a sandbox
   * tightened to deny exec refuses signals too, and silently doing nothing
   * there is indistinguishable from having killed it.
   */
  private async killCommand(cmdId: string, signal: number): Promise<void> {
    try {
      await this.transport.unary("SignalCommand", {
        sandboxId: this.id,
        commandId: cmdId,
        signal,
      });
    } catch (err) {
      if (err instanceof BurrowError && err.isAlreadyExited) return;
      throw err;
    }
  }

  /**
   * Creates a guest user with a private home directory.
   *
   * ```ts
   * const alice = await sandbox.createUser("alice");
   * await sandbox.exec("whoami", { user: alice.username });
   * ```
   *
   * The home is 0700, so one agent's files are not readable by another's.
   * Names are `[a-z_][a-z0-9_-]*`, at most 32 characters.
   */
  async createUser(name: string, options: CallOptions = {}): Promise<GuestUser> {
    const res = await this.withResume(() =>
      this.call<any>("CreateUser", { sandboxId: this.id, name }, options),
    );
    return {
      username: res.username ?? name,
      uid: Number(res.uid ?? 0),
      gid: Number(res.gid ?? 0),
      home: res.home ?? "",
    };
  }

  /**
   * Sets a guest account's password: root, or Administrator on Windows,
   * unless `user` names another.
   *
   * ```ts
   * const admin = await sandbox.setPassword();
   * console.log(admin.username, admin.password);
   * ```
   *
   * With no `password` one is generated and returned once; it is never
   * stored. `create` makes the account when it does not exist.
   */
  async setPassword(
    options: { user?: string; password?: string; create?: boolean } & CallOptions = {},
  ): Promise<PasswordSet> {
    const { user, password, create, ...call } = options;
    const res = await this.withResume(() =>
      this.call<any>(
        "SetPassword",
        {
          sandboxId: this.id,
          user: user ?? "",
          password: password ?? "",
          isCreatedIfMissing: create ?? false,
        },
        call,
      ),
    );
    return {
      username: res.username ?? "",
      password: res.password ?? "",
      created: Boolean(res.isCreated),
    };
  }

  /**
   * Creates a guest group and a directory its members share.
   *
   * The directory is group-owned and setgid, so a file one member creates in
   * it stays readable by the others.
   */
  async createGroup(name: string, options: CallOptions = {}): Promise<GuestGroup> {
    const res = await this.withResume(() =>
      this.call<any>("CreateGroup", { sandboxId: this.id, name }, options),
    );
    return {
      groupname: res.groupname ?? name,
      gid: Number(res.gid ?? 0),
      sharedDir: res.sharedDir ?? "",
    };
  }

  /**
   * Deletes a guest user that {@link createUser} could have made.
   *
   * Root, system and built-in accounts, administrators and the accounts the
   * agent relies on are refused, as is a user with a running process: end it
   * first. The user's own group goes with them. Their home is kept, handed to
   * root on Linux and macOS, unless `removeHome` is set.
   */
  async deleteUser(
    name: string,
    options: { removeHome?: boolean } & CallOptions = {},
  ): Promise<{ home: string; homeRemoved: boolean }> {
    const res = await this.withResume(() =>
      this.call<any>(
        "DeleteUser",
        { sandboxId: this.id, name, isHomeRemoved: options.removeHome ?? false },
        options,
      ),
    );
    return { home: res.home ?? "", homeRemoved: res.isHomeRemoved ?? false };
  }

  /**
   * Deletes a guest group that {@link createGroup} could have made.
   *
   * A group that is some user's primary group is refused; delete the user.
   * Members simply lose it. Its shared directory is kept, handed to root on
   * Linux and macOS, unless `removeSharedDir` is set.
   */
  async deleteGroup(
    name: string,
    options: { removeSharedDir?: boolean } & CallOptions = {},
  ): Promise<{ sharedDir: string; sharedDirRemoved: boolean }> {
    const res = await this.withResume(() =>
      this.call<any>(
        "DeleteGroup",
        { sandboxId: this.id, name, isSharedDirRemoved: options.removeSharedDir ?? false },
        options,
      ),
    );
    return {
      sharedDir: res.sharedDir ?? "",
      sharedDirRemoved: res.isSharedDirRemoved ?? false,
    };
  }

  /** Adds a user to a group, so the group's shared directory opens to them. */
  async addUserToGroup(user: string, group: string, options: CallOptions = {}): Promise<void> {
    await this.withResume(() =>
      this.call("AddUserToGroup", { sandboxId: this.id, user, group }, options),
    );
  }

  /** Removes a user from a group, closing the shared directory to them. */
  async removeUserFromGroup(user: string, group: string, options: CallOptions = {}): Promise<void> {
    await this.withResume(() =>
      this.call("RemoveUserFromGroup", { sandboxId: this.id, user, group }, options),
    );
  }

  /**
   * A handle onto the same sandbox that acts as `name`.
   *
   * ```ts
   * const alice = sandbox.asUser("alice");
   * await alice.exec("touch ~/notes.txt");
   * await alice.writeFile("/home/alice/todo.txt", "ship it\n");
   * ```
   *
   * Commands and terminals run as the user, and every file call is made as
   * them, so the guest kernel refuses what the user could not do and what
   * they create is theirs. `watch` is the exception: the guest scans as
   * root. The user has to exist already.
   */
  asUser(name: string): Sandbox {
    this.assertLive();
    // Shares the connection but does not own it: closing a user handle must
    // not close the sandbox's.
    const handle = new Sandbox(this.transport, this.info, this.handleOptions(), false);
    handle.defaultUser = name;
    return handle;
  }

  private handleOptions(): HandleOptions {
    return { env: this.env, autoResume: this.autoResume, onResume: this.onResume };
  }

  /**
   * Opens an interactive shell with a pty, for when input arrives over time
   * (a browser terminal, an agent driving a REPL). For a command that runs to
   * completion, use `exec`.
   */
  terminal(options: TerminalOptions = {}): Terminal {
    this.assertLive();
    return new Terminal(this.node(), this.id, { user: this.defaultUser, ...options });
  }

  /**
   * Publishes a port from inside the sandbox on its node's address. A host
   * port carries one protocol, so publishing TCP and UDP takes two calls.
   *
   * ```ts
   * const { url } = await sandbox.exposePort(8000);
   * ```
   */
  async exposePort(guestPort: number, options: ExposePortOptions = {}): Promise<PortMapping> {
    const res = await this.call<any>(
      "ExposePort",
      {
        sandboxId: this.id,
        guestPort,
        hostPort: options.hostPort ?? 0,
        isUdp: options.udp ?? false,
      },
      options,
    );
    return toPort(res, this.transport.host);
  }

  async listPorts(options: CallOptions = {}): Promise<PortMapping[]> {
    const res = await this.call<any>("ListPorts", { sandboxId: this.id }, options);
    return (res.ports ?? []).map((port: any) => toPort(port, this.transport.host));
  }

  /**
   * Where a published guest port answers.
   *
   * ```ts
   * await sandbox.exposePort(8000);
   * const url = await sandbox.domain(8000);
   * ```
   *
   * When the node holding the sandbox runs an edge, this is a full URL on a
   * per-sandbox hostname, `http://<port>-<sandbox-id>.<edge-domain>/`, and
   * traffic arriving on it wakes a suspended sandbox. When that node runs no
   * edge there is no hostname routing, and this is a bare `host:port` on the
   * node's own address. Throws when the port is not published.
   */
  async domain(guestPort: number, options: CallOptions = {}): Promise<string> {
    const ports = await this.listPorts(options);
    const mapping = ports.find((port) => port.guestPort === guestPort);
    if (!mapping) {
      throw new BurrowError(
        `port ${guestPort} is not published; call exposePort(${guestPort}) first`,
        "not_found",
      );
    }
    return mapping.edgeUrl ?? mapping.url.replace(/^https?:\/\//, "");
  }

  async closePort(hostPort: number, options: CallOptions = {}): Promise<void> {
    await this.call("ClosePort", { sandboxId: this.id, hostPort }, options);
  }

  /**
   * Shares the sandbox through a tailcat address.
   *
   * A share is a WireGuard tunnel bootstrapped over a DERP relay, dialed with
   * the `tailcat` CLI: no host port, no edge, and a connection wakes a
   * suspended sandbox. Calling it again reshapes an existing share and keeps
   * its address; `rotate` issues new keys and so a new address. TCP is shared
   * on every port unless `ports` narrows it; UDP only on `udpPorts`, or
   * everywhere with `allUdp`. The guest sees each client's own public IPv4
   * as the packet source unless `transparentIp` is `false`.
   *
   * ```ts
   * const share = await sandbox.share({ ports: [22] });
   * console.log(`tailcat ssh ${share.address}`);
   * ```
   */
  async share(options: ShareOptions = {}): Promise<Share> {
    const res = await this.call<any>(
      "ShareSandbox",
      {
        sandboxId: this.id,
        ports: options.ports ?? [],
        allowedClients: options.allowedClients ?? [],
        isRotating: options.rotate ?? false,
        udpPorts: options.udpPorts ?? [],
        isAllUdp: options.allUdp ?? false,
        isTransparentIp: options.transparentIp,
      },
      options,
    );
    return toShare(res);
  }

  /** The sandbox's share. Throws `not_found` when it has none. */
  async getShare(options: CallOptions = {}): Promise<Share> {
    return toShare(await this.call<any>("GetShare", { sandboxId: this.id }, options));
  }

  /** Revokes the share; its address stops working at once. */
  async unshare(options: CallOptions = {}): Promise<void> {
    await this.call("UnshareSandbox", { sandboxId: this.id }, options);
  }

  /**
   * Moves the clocks the sandbox is measured against, and how long its
   * snapshots are kept.
   *
   * An omitted field is left where it is, which is what lets `0` keep meaning
   * "unlimited" here as it does on create.
   *
   * ```ts
   * await sandbox.updateLifetime({ maxLifetimeSecs: 7200, snapshots: { keepLast: 3 } });
   * ```
   */
  updateLifetime(options: UpdateLifetimeOptions): Promise<SandboxInfo> {
    return this.mutate(
      "UpdateLifetime",
      {
        sandboxId: this.id,
        maxLifetimeSecs: options.maxLifetimeSecs,
        idleSuspendSecs: options.idleSuspendSecs,
        suspendedTtlSecs: options.suspendedTtlSecs,
        checkpointSecs: options.checkpointSecs,
        isMemoryCheckpointed: options.checkpointMemory,
        snapshotExpirationSecs: options.snapshots?.expirationSecs,
        snapshotKeepLast: options.snapshots?.keepLast,
        isEvictedSnapshotKept: options.snapshots?.keepEvicted,
      },
      options,
    );
  }

  /**
   * Changes the sandbox's vCPUs, memory, root disk and host limits. An
   * omitted field is left as it is.
   *
   * A running sandbox takes what its hypervisor can hotplug: a bigger disk
   * and memory under Firecracker and Cloud Hypervisor, and vCPUs under Cloud
   * Hypervisor on x86_64. Memory moves between what the sandbox booted with
   * and its `maxMemoryMib`; more is admitted against the node's memory like a
   * create. A guest unplugs only memory it can empty, so a shrink can come
   * back `partial`, its `value` being where it stopped. A shut-down one
   * ({@link stop}) takes everything: vCPUs and memory on its next boot, and
   * its disk at once, shrunk by a helper VM that checks the filesystem first.
   * A suspended sandbox takes none of it unless `boot` is set. A sandbox
   * that is not running is resized only if the new shape fits its node, and
   * otherwise throws `resource_exhausted` with nothing changed. The host
   * limits (`cpus`, `reservedCpus`, `cpuShares`, `cpusetCpus`, `blkioWeight`)
   * move live on a running sandbox and otherwise when it next runs, and what
   * the sandbox is charged is admitted against its node first. What cannot be
   * applied is reported as
   * `refused` with the reason rather than thrown, so check each field you
   * asked for.
   *
   * ```ts
   * const { memoryMib } = await sandbox.updateResources({ memoryMib: 3 * 1024 });
   * if (memoryMib?.change !== "live") console.log(memoryMib?.value, memoryMib?.reason);
   * ```
   */
  async updateResources(options: ResourceUpdateOptions): Promise<ResourcesUpdate> {
    for (const [name, value] of [
      ["vcpus", options.vcpus],
      ["memoryMib", options.memoryMib],
      ["diskMib", options.diskMib],
    ] as const) {
      if (value !== undefined && (!Number.isInteger(value) || value <= 0)) {
        throw new BurrowError(`${name} ${value} is not a positive integer`, "invalid_argument");
      }
    }
    const raw = await this.call<any>(
      "UpdateResources",
      {
        sandboxId: this.id,
        vcpus: options.vcpus,
        memMib: options.memoryMib,
        diskMib: options.diskMib,
        cpus: options.cpus,
        reservedCpus: options.reservedCpus,
        cpuShares: options.cpuShares,
        cpusetCpus: options.cpusetCpus,
        blkioWeight: options.blkioWeight,
        boot: options.boot,
      },
      // A shrink boots a helper VM that checks the filesystem first.
      { ...options, timeoutMs: options.timeoutMs ?? 600_000 },
    );
    if (raw.sandbox) this.info = toSandboxInfo(raw.sandbox);
    return toResourcesUpdate(raw);
  }

  /** Replaces the sandbox's tags. An empty map clears them. */
  updateTags(tags: Record<string, string>, options: CallOptions = {}): Promise<SandboxInfo> {
    return this.mutate("UpdateTags", { sandboxId: this.id, tags }, options);
  }

  /** Routes an allocated public IP to this sandbox. */
  async attachIp(address: string, options: CallOptions = {}): Promise<PublicIp> {
    const ip = toPublicIp(
      await this.call<any>("AttachIp", { address, sandboxId: this.id }, options),
    );
    await this.refresh(options);
    return ip;
  }

  /** Takes a public IP off this sandbox, keeping it allocated. */
  async detachIp(address: string, options: CallOptions = {}): Promise<PublicIp> {
    const ip = toPublicIp(await this.call<any>("DetachIp", { address }, options));
    await this.refresh(options);
    return ip;
  }

  /**
   * Replaces the sandbox's egress policy.
   *
   * Firewall rules, proxy allowlist, DNS filtering and header injection all
   * re-render at once, so the sandbox is never briefly half-governed.
   */
  updateNetworkPolicy(policy: NetworkInput, options: CallOptions = {}): Promise<SandboxInfo> {
    const wanted = resolveNetwork(policy);
    return this.mutate(
      "UpdateNetworkPolicy",
      { sandboxId: this.id, network: toNetworkPolicy(wanted) },
      options,
    );
  }

  /**
   * Replaces the sandbox's exec policy, its file policy, or both.
   *
   * A section you pass replaces that section wholesale, so a field left out of
   * it is an allowance withdrawn. A section you do not pass is left exactly as
   * it is, deliberately unlike create, where an omitted section means "no
   * restriction": on a live sandbox that reading would make tightening files a
   * silent re-opening of exec. Both are enforced on the node, before a command
   * or a path reaches the guest.
   *
   * ```ts
   * // Deny exec. The file policy, whatever it is, is untouched.
   * await sandbox.updateAccessPolicy({ exec: { allowExec: false } });
   * ```
   */
  async updateAccessPolicy(options: UpdateAccessOptions): Promise<SandboxInfo> {
    if (options.exec === undefined && options.fs === undefined) {
      throw new BurrowError(
        "updateAccessPolicy needs exec, fs or both: a call with neither would change nothing",
        "invalid_argument",
      );
    }
    return this.mutate(
      "UpdateAccessPolicy",
      {
        sandboxId: this.id,
        // Absent stays absent on the wire: presence is what carries "leave
        // this section alone" to the node.
        exec: toExecPolicy(options.exec),
        fs: toFsPolicy(options.fs),
      },
      options,
    );
  }

  /**
   * Snapshots the sandbox to disk and stops its VM. It keeps its filesystem,
   * its address and its memory, and rejects commands until it is resumed;
   * {@link delete} destroys one instead.
   */
  pause(options: CallOptions = {}): Promise<SandboxInfo> {
    return this.mutate("PauseSandbox", { sandboxId: this.id }, options);
  }

  /**
   * Restores a suspended sandbox, typically in a few hundred milliseconds.
   * One that was stopped has no memory to restore and is refused with
   * `failed_precondition`; {@link start} it instead.
   *
   * Every resume this handle performs goes through here, auto-resume included,
   * so this is the one place `onResume` has to fire.
   */
  async resume(options: CallOptions = {}): Promise<SandboxInfo> {
    const info = await this.mutate("ResumeSandbox", { sandboxId: this.id }, options);
    await this.onResume?.(this);
    return info;
  }

  /**
   * Shuts the VM down, keeping the writable disk and volumes. Unlike
   * {@link pause}, nothing in memory survives: processes end, and {@link start}
   * runs the image's init again on the same disk. For a Sandbox Kit template
   * that is the stop and start its spec describes, and the Kit's startup hooks
   * run again on the way up.
   */
  stop(options: CallOptions = {}): Promise<SandboxInfo> {
    return this.mutate("StopSandbox", { sandboxId: this.id }, options);
  }

  /**
   * Cold-boots a stopped sandbox on its existing disks. It takes as long as a
   * create, since there is no memory image to restore, and the sandbox keeps
   * its id, name, address and published ports. It boots its template's
   * current kernel unless `keepKernel`, which boots the one it last ran.
   */
  async start(options: StartOptions = {}): Promise<SandboxInfo> {
    const info = await this.mutate(
      "StartSandbox",
      { sandboxId: this.id, isKernelKept: options.keepKernel ?? false },
      options,
    );
    await this.onResume?.(this);
    return info;
  }

  /**
   * Replaces the root disk, discarding everything written to it but the
   * paths in `keep`, while keeping the sandbox's id, name, address and
   * volumes. The old disk is let go only once the new one has booted; a
   * failure leaves the sandbox as it was. With `template` the sandbox moves
   * onto another template; a Kit is provisioned again on the new disk with
   * the recorded inputs, as changed by `kit`.
   */
  async recreate(options: RecreateOptions = {}): Promise<SandboxInfo> {
    const info = await this.mutate(
      "RecreateSandbox",
      {
        sandboxId: this.id,
        template: options.template ?? "",
        kit: toKitSpec(options.kit),
        keep: options.keep ?? [],
      },
      options,
    );
    await this.onResume?.(this);
    return info;
  }

  /**
   * Every VM this sandbox has run, newest first.
   *
   * A sandbox outlives its VMs: {@link pause} ends one and {@link resume}
   * starts the next. The node keeps only the most recent sessions of each
   * sandbox, and drops them all when the sandbox is deleted.
   *
   * ```ts
   * const [current] = await sandbox.listSessions();
   * console.log(current.startedBy, current.startedAt);
   * ```
   */
  async listSessions(options: CallOptions = {}): Promise<Session[]> {
    const res = await this.call<any>("ListSessions", { sandboxId: this.id }, options);
    return (res.sessions ?? []).map(toSession);
  }

  /**
   * The end of the sandbox's serial console as its node captured it since its
   * VM last started: the guest kernel's boot and anything printed there.
   * `tailBytes` is how much of the end, 64 KiB by default and at most 2 MiB;
   * `isTruncated` says the log holds more before it.
   */
  async console(
    options: CallOptions & { tailBytes?: number } = {},
  ): Promise<{ text: string; isTruncated: boolean }> {
    const res = await this.call<any>(
      "GetConsole",
      { sandboxId: this.id, tailBytes: options.tailBytes ?? 0 },
      options,
    );
    return { text: res.text ?? "", isTruncated: res.isTruncated ?? false };
  }

  /**
   * The VM the sandbox is running now, or `undefined` when it has none.
   *
   * The open session is the one {@link listSessions} reports with no
   * `endedBy`.
   */
  async currentSession(options: CallOptions = {}): Promise<Session | undefined> {
    const sessions = await this.listSessions(options);
    return sessions.find((session) => session.endedBy === null);
  }

  /**
   * Creates a sandbox from this one's current state.
   *
   * This sandbox keeps running; a running source's state is written first, so
   * the child starts from its state as of the call. The child lands on the same
   * node, because a snapshot and its disks are node-local files.
   *
   * ```ts
   * const child = await sandbox.fork();
   * const branch = await sandbox.fork({ networkPolicy: "none" });
   * ```
   */
  async fork(options: ForkOptions = {}): Promise<Sandbox> {
    const raw = await this.transport.unary<any, any>(
      "ForkSandbox",
      this.forkRequest(options),
      options.timeoutMs ?? 120_000,
      options.signal,
    );
    // A fork is the same sandbox again, so it runs commands with the same
    // environment this handle applies, and holds its own share of the
    // connection.
    return new Sandbox(this.transport.retain(), toSandboxInfo(raw), this.handleOptions());
  }

  /** Builds a `ForkSandboxRequest`. An omitted policy inherits the source's. */
  private forkRequest(options: ForkOptions): any {
    this.assertLive();
    const network = options.networkPolicy;
    const reshaped =
      options.vcpus !== undefined ||
      options.memoryMib !== undefined ||
      options.diskMib !== undefined;
    const stated =
      reshaped ||
      network !== undefined ||
      options.networks !== undefined ||
      options.exec !== undefined ||
      options.fs !== undefined;
    const policy = !stated
      ? undefined
      : {
          resources: reshaped
            ? {
                vcpus: options.vcpus ?? 0,
                memMib: options.memoryMib ?? 0,
                diskMib: options.diskMib ?? 0,
              }
            : undefined,
          network: network === undefined ? undefined : toNetworkPolicy(resolveNetwork(network)),
          networks: toNetworks(options.networks, options.alias),
          // Each section is inherited on its own, so overriding one does not
          // strip the others off the child.
          exec: toExecPolicy(options.exec),
          fs: toFsPolicy(options.fs),
        };
    return {
      sandboxId: this.id,
      name: options.name ?? "",
      policy,
      nodeLabels: options.nodeLabels ?? {},
    };
  }

  /**
   * Moves the sandbox to another node through the object store.
   *
   * A running sandbox is suspended, carried over and resumed. It keeps its id,
   * name and policy and gets an address on the new node. Durable volumes it
   * mounts move with it; one mounting a volume that is not durable cannot move.
   *
   * ```ts
   * await sandbox.move({ nodeLabels: { tier: "dedicated" } });
   * ```
   */
  move(options: MoveOptions = {}): Promise<SandboxInfo> {
    return this.mutate(
      "MoveSandbox",
      {
        sandboxId: this.id,
        nodeId: options.nodeId ?? "",
        nodeLabels: options.nodeLabels ?? {},
        isCpusetDropped: options.dropCpuset ?? false,
      },
      options,
      300_000,
    );
  }

  /**
   * Saves the sandbox's state as a snapshot object and keeps running.
   *
   * The guest is paused only long enough to write its state. Unlike the
   * sandbox's own suspend state, which dies with it, a snapshot outlives its
   * source and can start any number of new sandboxes:
   *
   * ```ts
   * const snapshot = await prepared.snapshot({ expirationSecs: 86_400 });
   * const worker = await Sandbox.create({ snapshot: snapshot.id });
   * ```
   */
  async snapshot(options: SnapshotOptions = {}): Promise<Snapshot> {
    this.assertLive();
    const raw = await this.transport.unary<any, any>(
      "CreateSnapshot",
      { sandboxId: this.id, expirationSecs: options.expirationSecs ?? 0 },
      // Writing a memory image and cloning a disk; seconds, not
      // milliseconds, on a large guest.
      options.timeoutMs ?? 120_000,
      options.signal,
    );
    return new Snapshot(this.transport.retain(), raw);
  }

  /**
   * Destroys the sandbox and everything in it. The handle is inert
   * afterwards: every later call throws rather than failing obscurely against
   * an id that is no longer anywhere.
   */
  async delete(options: CallOptions = {}): Promise<void> {
    try {
      await this.call("DeleteSandbox", { sandboxId: this.id }, options);
    } finally {
      this.destroyed = true;
      if (this.owned) this.transport.close();
    }
  }

  /** Releases the connection without destroying the sandbox. */
  close(): void {
    if (this.owned) this.transport.close();
  }

  /**
   * Destroys the sandbox when it leaves scope.
   *
   * ```ts
   * await using sandbox = await Sandbox.create({ template: "python" });
   * ```
   */
  async [Symbol.asyncDispose](): Promise<void> {
    await this.delete();
  }
}
