import { attach, SandboxChildProcess, type ChildProcess } from "./child-process.js";
import { withClient } from "./client.js";
import { BurrowError } from "./errors.js";
import { SandboxFs } from "./fs.js";
import type { GuestLink } from "./guest.js";
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
import type { Transport, TransportOptions } from "./transport.js";
import type {
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
  PortMapping,
  RecreateOptions,
  SandboxInfo,
  SandboxState,
  Session,
  SessionEnd,
  SessionStart,
  Share,
  ShareOptions,
  UpdateAccessOptions,
  UpdateLifetimeOptions,
  Usage,
} from "./types.js";
import { dateOf, dateOrNull, enumOf } from "./wire.js";

const STATES: readonly SandboxState[] = [
  "creating",
  "running",
  "paused",
  "suspended",
  "stopped",
  "stopping",
  "destroyed",
  "failed",
];
const SESSION_STARTS: readonly SessionStart[] = ["boot", "restore", "resume"];
const SESSION_ENDS: readonly SessionEnd[] = ["suspended", "deleted", "failed", "stopped"];
const COMMAND_STATES: readonly CommandState[] = ["running", "exited"];

/** @internal One `Sandbox` record as the SDK reports it. */
export function toSandboxInfo(raw: any): SandboxInfo {
  return {
    id: raw.id,
    name: raw.name ?? "",
    nodeId: raw.nodeId ?? "",
    template: raw.template ?? "",
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
    guestOs: raw.guestOs ?? "",
  };
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
  /** What `fs` and `childProcess` reach the sandbox through, read live. */
  private readonly link: GuestLink;
  /**
   * The sandbox's filesystem, as Node's `fs/promises`: the same functions,
   * signatures and errors, performed by the guest kernel.
   */
  readonly fs: SandboxFs;
  /** Commands in the sandbox, as Node's `child_process`: `spawn`, `exec`, `execFile`. */
  readonly childProcess: SandboxChildProcess;

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
    this.link = {
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
    this.fs = new SandboxFs(this.link);
    this.childProcess = new SandboxChildProcess(this.link);
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
      },
      tags: options.tags ?? {},
      nodeLabels: options.nodeLabels ?? {},
      kit: toKitSpec(options.kit),
    };
  }

  /**
   * Creates a sandbox and waits for it to be ready to accept commands.
   *
   * Opens a connection for this one sandbox; a {@link Burrow} client shares
   * one across many.
   */
  static create(options: CreateOptions & TransportOptions = {}): Promise<Sandbox> {
    return withClient(options, (burrow) => burrow.sandboxes.create(options));
  }

  /**
   * Returns the sandbox with this name, creating it if it is not there.
   *
   * ```ts
   * const sandbox = await Sandbox.getOrCreate({
   *   name: "build-482",
   *   template: "python-tools",
   *   onCreate: (s) => s.fs.writeFile("/work/app.py", src),
   * });
   * ```
   */
  static getOrCreate(options: GetOrCreateOptions & TransportOptions = {}): Promise<Sandbox> {
    return withClient(options, (burrow) => burrow.sandboxes.getOrCreate(options));
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
    return attach(this.link, cmdId, options.fromOffset ?? 0, toCommandInfo(raw).cmd);
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
   * await sandbox.childProcess.exec("whoami", { user: alice.username });
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
   * await alice.childProcess.exec("touch ~/notes.txt");
   * await alice.fs.writeFile("/home/alice/todo.txt", "ship it\n");
   * ```
   *
   * Commands and terminals run as the user, and every `fs` call is made as
   * them, so the guest kernel refuses what the user could not do and what
   * they create is theirs. `fs.watch` is the exception: the guest scans as
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
   * completion, use `childProcess.exec`.
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
   * Moves the clocks the sandbox is measured against.
   *
   * An omitted field is left where it is, which is what lets `0` keep meaning
   * "unlimited" here as it does on create. The machine shape is not among
   * them: a running VM's configuration is fixed.
   */
  updateLifetime(options: UpdateLifetimeOptions): Promise<SandboxInfo> {
    return this.mutate(
      "UpdateLifetime",
      {
        sandboxId: this.id,
        maxLifetimeSecs: options.maxLifetimeSecs,
        idleSuspendSecs: options.idleSuspendSecs,
        suspendedTtlSecs: options.suspendedTtlSecs,
      },
      options,
    );
  }

  /** Replaces the sandbox's tags. An empty map clears them. */
  updateTags(tags: Record<string, string>, options: CallOptions = {}): Promise<SandboxInfo> {
    return this.mutate("UpdateTags", { sandboxId: this.id, tags }, options);
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
   * its id, name, address and published ports.
   */
  async start(options: CallOptions = {}): Promise<SandboxInfo> {
    const info = await this.mutate("StartSandbox", { sandboxId: this.id }, options);
    await this.onResume?.(this);
    return info;
  }

  /**
   * Replaces the root disk, discarding everything written to it, while
   * keeping the sandbox's id, name, address and volumes. With `template` the
   * sandbox moves onto another template; a Kit is provisioned again on the
   * new disk with the recorded inputs, as changed by `kit`.
   */
  async recreate(options: RecreateOptions = {}): Promise<SandboxInfo> {
    const info = await this.mutate(
      "RecreateSandbox",
      { sandboxId: this.id, template: options.template ?? "", kit: toKitSpec(options.kit) },
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
    const stated =
      network !== undefined ||
      options.networks !== undefined ||
      options.exec !== undefined ||
      options.fs !== undefined;
    const policy = !stated
      ? undefined
      : {
          // Resources are absent deliberately: a restore takes its machine
          // configuration from the snapshot, and the node refuses an override.
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
   * name and policy and gets an address on the new node. Volumes do not move.
   *
   * ```ts
   * await sandbox.move({ nodeLabels: { tier: "dedicated" } });
   * ```
   */
  move(options: MoveOptions = {}): Promise<SandboxInfo> {
    return this.mutate(
      "MoveSandbox",
      { sandboxId: this.id, nodeId: options.nodeId ?? "", nodeLabels: options.nodeLabels ?? {} },
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
      // Writing a memory image and copying a scratch disk; seconds, not
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
