import { attach, SandboxChildProcess, type ChildProcess } from "./child-process.js";
import { BurrowError } from "./errors.js";
import { SandboxFs } from "./fs.js";
import type { GuestLink } from "./guest.js";
import {
  fromPolicy,
  resolveNetwork,
  toExecPolicy,
  toFsPolicy,
  toNetworkPolicy,
  toNetworks,
  toVolumeMounts,
  toResourcePolicy,
} from "./policy.js";
import { Snapshot, type SnapshotOptions } from "./snapshot.js";
import { Terminal, type TerminalOptions } from "./terminal.js";
import { Transport, type TransportOptions } from "./transport.js";
import type {
  AuditEvent,
  AuditQuery,
  CommandInfo,
  CreateOptions,
  EventsOptions,
  ForkOptions,
  GetOptions,
  GetOrCreateOptions,
  GuestGroup,
  GuestUser,
  KitOptions,
  LifecycleEvent,
  ListOptions,
  MoveOptions,
  NodeInfo,
  PortMapping,
  RecreateOptions,
  Share,
  ShareOptions,
  SandboxInfo,
  SandboxState,
  Session,
  SessionEnd,
  SessionStart,
  UpdateOptions,
  Usage,
} from "./types.js";

function toSandboxInfo(raw: any): SandboxInfo {
  return {
    id: raw.id,
    name: raw.name ?? "",
    nodeId: raw.nodeId ?? "",
    template: raw.template ?? "",
    state: stateOf(raw.state),
    createdAt: raw.createdAt ?? "",
    guestIp: raw.guestIp ?? "",
    tags: raw.metadata ?? {},
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
  };
}

function toSession(raw: any): Session {
  return {
    id: raw.id ?? "",
    sandboxId: raw.sandboxId ?? "",
    startedAt: raw.startedAt ?? "",
    endedAt: raw.endedAt ?? "",
    // A reason this client has no name for reads as "unknown" rather than
    // passing a string through that callers branch on.
    startedBy: (["boot", "restore", "resume"] as string[]).includes(raw.startedBy)
      ? (raw.startedBy as SessionStart)
      : "unknown",
    endedBy: (["suspended", "deleted", "failed", "unknown", ""] as string[]).includes(
      raw.endedBy ?? "",
    )
      ? ((raw.endedBy ?? "") as SessionEnd | "")
      : "unknown",
  };
}

function stateOf(state: string | number | undefined): SandboxState {
  const name = String(state ?? "").replace("SANDBOX_STATE_", "").toLowerCase();
  const known: SandboxState[] = [
    "creating",
    "running",
    "paused",
    "suspended",
    "stopped",
    "stopping",
    "destroyed",
    "failed",
  ];
  return (known as string[]).includes(name) ? (name as SandboxState) : "unknown";
}

/** Builds a `CreateSandboxRequest`. */
function toCreateRequest(options: CreateOptions): any {
  const network = resolveNetwork(options.networkPolicy);
  const resources = options.resources ?? {};
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
      resources: toResourcePolicy(resources),
      // Left off the request entirely unless the caller asked for a limit:
      // absent is what the node reads as "allowed".
      exec: toExecPolicy(options.exec),
      fs: toFsPolicy(options.fs),
      network: toNetworkPolicy(network),
      networks: toNetworks(options.networks, options.alias),
      volumes: toVolumeMounts(options.volumes),
    },
    metadata: options.tags ?? {},
    nodeLabels: options.nodeLabels ?? {},
    kit: toKitSpec(options.kit),
  };
}

/** Builds a `KitSpec`. Absent inputs are sent empty, which the node reads as none. */
function toKitSpec(kit: KitOptions | undefined): any {
  return {
    args: kit?.args ?? {},
    env: kit?.env ?? {},
    rejectTypes: [...(kit?.rejectCapabilities ?? [])],
  };
}

/** Turns a guest's report of one command into the SDK's shape. */
function toCommandInfo(raw: any): CommandInfo {
  const ended = Number(raw.endedAtUnixMs ?? 0);
  const state = String(raw.state ?? "");
  return {
    cmdId: raw.commandId ?? "",
    cmd: raw.cmd ?? [],
    user: raw.user ?? "",
    state:
      state === "running" || state === "exited"
        ? (state as CommandInfo["state"])
        : "unknown",
    exitCode: Number(raw.exitCode ?? 0),
    startedAt: new Date(Number(raw.startedAtUnixMs ?? 0)),
    endedAt: ended > 0 ? new Date(ended) : null,
    bufferedBytes: Number(raw.bufferedBytes ?? 0),
    exitSignal: Number(raw.exitSignal ?? 0),
    outputBytes: Number(raw.outputBytes ?? 0),
  };
}

/**
 * How many times {@link Sandbox.getOrCreate} looks before giving up. Only a
 * lost race gets this far, waiting on another caller's create to finish.
 */
const GET_OR_CREATE_ATTEMPTS = 10;

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * A sandbox.
 *
 * Obtained from {@link Sandbox.create}, {@link Sandbox.get} or
 * {@link Sandbox.fork}; not constructed directly.
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
  private env: Record<string, string>;
  /**
   * Guest user every command from this handle runs as. Empty is root.
   *
   * Set only on a handle from {@link asUser}; a per-command `user` still wins.
   */
  private defaultUser = "";
  /** Called after this handle resumes the sandbox, including auto-resume. */
  private onResume?: (sandbox: Sandbox) => void | Promise<void>;
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

  private constructor(
    transport: Transport,
    info: SandboxInfo,
    owned: boolean,
    autoResume = true,
    env: Record<string, string> = {},
  ) {
    this.transport = transport;
    this.info = info;
    this.id = info.id;
    this.owned = owned;
    this.autoResume = autoResume;
    this.env = env;
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

  /**
   * Refuses a call on a deleted sandbox. `delete` released the connection, so
   * the alternative is an obscure transport failure some calls later.
   */
  private assertLive(): void {
    if (this.destroyed) {
      throw new BurrowError(
        `sandbox ${this.id} was deleted`,
        "failed_precondition",
      );
    }
  }

  /** Creates a sandbox and waits for it to be ready to accept commands. */
  static async create(
    options: CreateOptions & TransportOptions = {},
  ): Promise<Sandbox> {
    const transport = new Transport(options);
    try {
      const raw = await transport.unary<any, any>(
        "CreateSandbox",
        toCreateRequest(options),
        options.timeoutMs ?? 120_000,
        options.signal,
      );
      return new Sandbox(
        transport,
        toSandboxInfo(raw),
        true,
        options.autoResume ?? true,
        options.env ?? {},
      );
    } catch (err) {
      transport.close();
      throw err;
    }
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
   *
   * A `name` is the only key: ids are generated by the server, so there is no
   * id to ask for before the sandbox exists. The create options apply only
   * when it turns out not to exist, so the same call is safe from every
   * worker; an existing sandbox is handed back as it is. A stopped one stays
   * stopped unless `resume` is set, though the first call that needs a running
   * VM resumes it anyway.
   */
  static async getOrCreate(
    options: GetOrCreateOptions & TransportOptions = {},
  ): Promise<Sandbox> {
    const key = options.name;
    if (!key) {
      throw new BurrowError(
        "getOrCreate needs a name: without one there is nothing to get",
        "invalid_argument",
      );
    }

    // Two processes racing on the same name both find nothing and both create.
    // The loser is told ALREADY_EXISTS while the winner's sandbox is still
    // booting, so the get is retried rather than made once.
    for (let attempt = 0; attempt < GET_OR_CREATE_ATTEMPTS; attempt++) {
      try {
        const sandbox = await Sandbox.get({ ...options, id: key });
        sandbox.env = options.env ?? {};
        sandbox.onResume = options.onResume;
        if (options.resume && (sandbox.state === "paused" || sandbox.state === "suspended")) {
          await sandbox.resume();
        }
        return sandbox;
      } catch (err) {
        if (!(err instanceof BurrowError) || err.code !== "not_found") throw err;
      }

      try {
        const sandbox = await Sandbox.create(options);
        sandbox.onResume = options.onResume;
        await options.onCreate?.(sandbox);
        return sandbox;
      } catch (err) {
        const lost =
          err instanceof BurrowError && err.code === "already_exists";
        if (!lost) throw err;
        // The winner's record appears once the node has built the sandbox.
        await delay(Math.min(200 * 2 ** attempt, 1_000));
      }
    }
    throw new BurrowError(
      `sandbox ${key} is being created elsewhere and did not become available`,
      "unavailable",
    );
  }

  /**
   * Returns a handle for a sandbox that already exists.
   *
   * ```ts
   * const sandbox = await Sandbox.get({ sandboxId: "sbx_..." });
   * ```
   */
  static async get(
    options: (GetOptions | string) & TransportOptions,
  ): Promise<Sandbox> {
    const params: GetOptions & TransportOptions =
      typeof options === "string" ? { id: options } : options;
    // Ids and names share one lookup: the server resolves a reference as an
    // id first and as a name second, and the two cannot collide.
    const id = params.sandboxId ?? params.id ?? params.name;
    if (!id) {
      throw new BurrowError("an id or a name is required", "invalid_argument");
    }

    const transport = new Transport(params);
    try {
      const raw = await transport.unary<any, any>(
        "GetSandbox",
        { id },
        params.timeoutMs,
        params.signal,
      );
      return new Sandbox(
        transport,
        toSandboxInfo(raw),
        true,
        params.autoResume ?? true,
      );
    } catch (err) {
      transport.close();
      throw err;
    }
  }

  /**
   * Lists sandboxes, newest state first, as an async iterable of handles.
   *
   * ```ts
   * for await (const sandbox of Sandbox.list({ tag: "owner=ci" })) {
   *   await sandbox.stop();
   * }
   * ```
   *
   * The handles share one connection, released once the last of them is closed
   * and the iteration has finished.
   */
  static list(
    options: ListOptions & TransportOptions = {},
  ): AsyncIterable<Sandbox> & { toArray(): Promise<Sandbox[]> } {
    const iterate = async function* (): AsyncGenerator<Sandbox> {
      const transport = new Transport(options);
      try {
        const res = await transport.unary<any, any>(
          "ListSandboxes",
          { tag: options.tag ?? "" },
          options.timeoutMs,
          options.signal,
        );
        for (const raw of res.sandboxes ?? []) {
          yield new Sandbox(transport.retain(), toSandboxInfo(raw), true);
        }
      } finally {
        transport.close();
      }
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

  /** @internal: used by {@link Burrow} so clients share one connection. */
  static adopt(transport: Transport, raw: any): Sandbox {
    return new Sandbox(transport, toSandboxInfo(raw), false);
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

  /**
   * Whether the node hosting this sandbox has missed its heartbeats. When
   * true, `state` and `status` are stale readings and calls fail with
   * `unavailable` until it returns. `delete()` still works: the orchestrator
   * drops the sandbox on its own word and destroys it if the node comes back.
   */
  get unreachable(): boolean {
    return this.info.unreachable;
  }

  /** Tags, as of the last call that returned the sandbox record. */
  get tags(): Record<string, string> {
    return this.info.tags;
  }

  get vcpus(): number {
    return this.info.policy.resources.vcpus;
  }

  /** The same number under its unit-bearing name. */
  get memoryMib(): number {
    return this.info.policy.resources.memoryMib;
  }

  /**
   * What the sandbox has consumed, as of the last call that returned its
   * record; {@link refresh} for a current reading. Accumulated across every VM
   * it has run, so a stop and a resume do not reset it.
   */
  get usage(): Usage {
    return this.info.usage;
  }

  /** RFC 3339. There is no `updatedAt`: the record does not carry one. */
  get createdAt(): string {
    return this.info.createdAt;
  }

  /** The whole policy in force, with injected header values redacted. */
  get policy() {
    return this.info.policy;
  }

  /** Re-reads the sandbox's current state from the server. */
  async refresh(options: { signal?: AbortSignal } = {}): Promise<SandboxInfo> {
    this.assertLive();
    const raw = await this.transport.unary<any, any>(
      "GetSandbox",
      { id: this.id },
      undefined,
      options.signal,
    );
    this.info = toSandboxInfo(raw);
    return this.info;
  }

  /**
   * Runs `op`, resuming the sandbox and retrying once if it is suspended.
   *
   * The daemon answers a call that needs a live guest with
   * `FAILED_PRECONDITION: sandbox is suspended; resume it first`, and nothing
   * else in the API reports that, so it is specific enough to act on.
   */
  private async withResume<T>(
    op: () => Promise<T>,
    enabled = this.autoResume,
  ): Promise<T> {
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
  async listCommands(
    options: { signal?: AbortSignal } = {},
  ): Promise<CommandInfo[]> {
    this.assertLive();
    const res = await this.transport.unary<any, any>(
      "ListCommands",
      { sandboxId: this.id },
      undefined,
      options.signal,
    );
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
  async getCommand(
    cmdId: string,
    options: { signal?: AbortSignal; fromOffset?: number } = {},
  ): Promise<ChildProcess> {
    this.assertLive();
    // Read first, so a bad id fails here rather than as an `error` event.
    const raw = await this.transport.unary<any, any>(
      "GetCommand",
      { sandboxId: this.id, commandId: cmdId },
      undefined,
      options.signal,
    );
    return attach(this.link, cmdId, options.fromOffset ?? 0, toCommandInfo(raw).cmd);
  }

  /**
   * Removes finished commands and their output, as `docker container prune`
   * does. Running commands are left alone.
   */
  async pruneCommands(
    options: { signal?: AbortSignal } = {},
  ): Promise<{ removed: number; freedBytes: number }> {
    this.assertLive();
    const res = await this.transport.unary<any, any>(
      "PruneCommands",
      { sandboxId: this.id },
      undefined,
      options.signal,
    );
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
  async createUser(
    name: string,
    options: { signal?: AbortSignal } = {},
  ): Promise<GuestUser> {
    this.assertLive();
    const res = await this.withResume(() =>
      this.transport.unary<any, any>(
        "CreateUser",
        { sandboxId: this.id, name },
        undefined,
        options.signal,
      ),
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
  async createGroup(
    name: string,
    options: { signal?: AbortSignal } = {},
  ): Promise<GuestGroup> {
    this.assertLive();
    const res = await this.withResume(() =>
      this.transport.unary<any, any>(
        "CreateGroup",
        { sandboxId: this.id, name },
        undefined,
        options.signal,
      ),
    );
    return {
      groupname: res.groupname ?? name,
      gid: Number(res.gid ?? 0),
      sharedDir: res.sharedDir ?? "",
    };
  }

  /** Adds a user to a group, so the group's shared directory opens to them. */
  async addUserToGroup(
    user: string,
    group: string,
    options: { signal?: AbortSignal } = {},
  ): Promise<void> {
    await this.membership("AddUserToGroup", user, group, options.signal);
  }

  /** Removes a user from a group, closing the shared directory to them. */
  async removeUserFromGroup(
    user: string,
    group: string,
    options: { signal?: AbortSignal } = {},
  ): Promise<void> {
    await this.membership("RemoveUserFromGroup", user, group, options.signal);
  }

  private async membership(
    method: string,
    user: string,
    group: string,
    signal?: AbortSignal,
  ): Promise<void> {
    this.assertLive();
    await this.withResume(() =>
      this.transport.unary(
        method,
        { sandboxId: this.id, user, group },
        undefined,
        signal,
      ),
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
    const handle = new Sandbox(
      this.transport,
      this.info,
      false,
      this.autoResume,
      this.env,
    );
    handle.defaultUser = name;
    return handle;
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
  async exposePort(
    guestPort: number,
    hostPort?: number | { hostPort?: number; udp?: boolean; signal?: AbortSignal },
  ): Promise<PortMapping> {
    this.assertLive();
    const options =
      typeof hostPort === "number" ? { hostPort } : (hostPort ?? {});
    const res = await this.transport.unary<any, any>(
      "ExposePort",
      {
        sandboxId: this.id,
        guestPort,
        hostPort: options.hostPort ?? 0,
        isUdp: options.udp ?? false,
      },
      undefined,
      options.signal,
    );
    return toPort(res, this.transport.host);
  }

  async listPorts(options: { signal?: AbortSignal } = {}): Promise<PortMapping[]> {
    this.assertLive();
    const res = await this.transport.unary<any, any>(
      "ListPorts",
      { id: this.id },
      undefined,
      options.signal,
    );
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
   * traffic arriving on it wakes a stopped sandbox. When that node runs no
   * edge there is no hostname routing, and this is a bare `host:port` on the
   * node's own address. Throws when the port is not published.
   */
  async domain(
    guestPort: number,
    options: { signal?: AbortSignal } = {},
  ): Promise<string> {
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

  async closePort(
    hostPort: number,
    options: { signal?: AbortSignal } = {},
  ): Promise<void> {
    this.assertLive();
    await this.transport.unary(
      "ClosePort",
      { sandboxId: this.id, hostPort },
      undefined,
      options.signal,
    );
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
   * as the packet source; `noTransparentIp` sources from the gateway.
   *
   * ```ts
   * const share = await sandbox.share({ ports: [22] });
   * console.log(`tailcat ssh ${share.address}`);
   * ```
   */
  async share(options: ShareOptions = {}): Promise<Share> {
    this.assertLive();
    const res = await this.transport.unary<any, any>(
      "ShareSandbox",
      {
        sandboxId: this.id,
        ports: options.ports ?? [],
        allowedClients: options.allowedClients ?? [],
        isRotating: options.rotate ?? false,
        udpPorts: options.udpPorts ?? [],
        isAllUdp: options.allUdp ?? false,
        isTransparentIpDisabled: options.noTransparentIp ?? false,
      },
      undefined,
      options.signal,
    );
    return toShare(res);
  }

  /** The sandbox's share. Throws `not_found` when it has none. */
  async getShare(options: { signal?: AbortSignal } = {}): Promise<Share> {
    this.assertLive();
    const res = await this.transport.unary<any, any>(
      "GetShare",
      { id: this.id },
      undefined,
      options.signal,
    );
    return toShare(res);
  }

  /** Revokes the share; its address stops working at once. */
  async unshare(options: { signal?: AbortSignal } = {}): Promise<void> {
    this.assertLive();
    await this.transport.unary(
      "UnshareSandbox",
      { id: this.id },
      undefined,
      options.signal,
    );
  }

  /**
   * Moves the clocks the sandbox is measured against.
   *
   * An omitted field is left where it is, which is what lets `0` keep meaning
   * "unlimited" here as it does on create. The machine shape is not among
   * them: a running VM's configuration is fixed.
   */
  async updateResources(
    options: Pick<
      UpdateOptions,
      "maxLifetimeSecs" | "idleSuspendSecs" | "suspendedTtlSecs" | "signal"
    >,
  ): Promise<SandboxInfo> {
    this.assertLive();
    const raw = await this.transport.unary<any, any>(
      "UpdateResources",
      {
        ref: { id: this.id },
        maxLifetimeSecs: options.maxLifetimeSecs,
        idleSuspendSecs: options.idleSuspendSecs,
        suspendedTtlSecs: options.suspendedTtlSecs,
      },
      undefined,
      options.signal,
    );
    this.info = toSandboxInfo(raw);
    return this.info;
  }

  /** Replaces the sandbox's tags. An empty map clears them. */
  async updateTags(
    tags: Record<string, string>,
    options: { signal?: AbortSignal } = {},
  ): Promise<SandboxInfo> {
    this.assertLive();
    const raw = await this.transport.unary<any, any>(
      "UpdateTags",
      { ref: { id: this.id }, tags },
      undefined,
      options.signal,
    );
    this.info = toSandboxInfo(raw);
    return this.info;
  }

  /**
   * Replaces the sandbox's egress policy.
   *
   * Firewall rules, proxy allowlist, DNS filtering and header injection all
   * re-render at once, so the sandbox is never briefly half-governed.
   */
  async updateNetworkPolicy(
    policy: UpdateOptions["networkPolicy"],
    options: { signal?: AbortSignal } = {},
  ): Promise<SandboxInfo> {
    this.assertLive();
    const wanted = resolveNetwork(policy);
    // The guest is handed the inspection CA during its first handshake, so a
    // sandbox that did not start with TLS inspection cannot gain it. That
    // makes this the one policy change refused here rather than sent.
    if (wanted.inspectTls && !this.info.policy.network.inspectTls) {
      throw new BurrowError(
        `sandbox ${this.id} was created without TLS inspection, so headers cannot be injected into its traffic; create it with inspectTls: true`,
        "failed_precondition",
      );
    }
    const raw = await this.transport.unary<any, any>(
      "UpdateNetworkPolicy",
      {
        ref: { id: this.id },
        network: toNetworkPolicy(wanted),
      },
      undefined,
      options.signal,
    );
    this.info = toSandboxInfo(raw);
    return this.info;
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
  async updateAccessPolicy(
    policy: Pick<UpdateOptions, "exec" | "fs">,
    options: { signal?: AbortSignal } = {},
  ): Promise<SandboxInfo> {
    this.assertLive();
    if (policy.exec === undefined && policy.fs === undefined) {
      throw new BurrowError(
        "updateAccessPolicy needs exec, fs or both: a call with neither would change nothing",
        "invalid_argument",
      );
    }
    const raw = await this.transport.unary<any, any>(
      "UpdateAccessPolicy",
      {
        ref: { id: this.id },
        // Absent stays absent on the wire: presence is what carries "leave
        // this section alone" to the node.
        exec: toExecPolicy(policy.exec),
        fs: toFsPolicy(policy.fs),
      },
      undefined,
      options.signal,
    );
    this.info = toSandboxInfo(raw);
    return this.info;
  }

  /**
   * Snapshots the sandbox to disk and stops its VM. It keeps its filesystem,
   * its address and its memory, and rejects commands until it is resumed;
   * {@link delete} destroys one instead.
   */
  async stop(options: { signal?: AbortSignal } = {}): Promise<SandboxInfo> {
    this.assertLive();
    const raw = await this.transport.unary<any, any>(
      "PauseSandbox",
      { id: this.id },
      undefined,
      options.signal,
    );
    this.info = toSandboxInfo(raw);
    return this.info;
  }

  /**
   * Restores a stopped sandbox, typically in a few hundred milliseconds.
   *
   * Every resume this handle performs goes through here, auto-resume included,
   * so this is the one place `onResume` has to fire.
   */
  async resume(options: { signal?: AbortSignal } = {}): Promise<SandboxInfo> {
    this.assertLive();
    const raw = await this.transport.unary<any, any>(
      "ResumeSandbox",
      { id: this.id },
      undefined,
      options.signal,
    );
    this.info = toSandboxInfo(raw);
    await this.onResume?.(this);
    return this.info;
  }

  /**
   * Shuts the VM down, keeping the writable disk and volumes. Unlike
   * {@link stop}, nothing in memory survives: processes end, and {@link boot}
   * runs the image's init again on the same disk. For a Sandbox Kit template
   * that is the stop and start its spec describes, and the Kit's startup hooks
   * run again on the way up.
   */
  async shutdown(options: { signal?: AbortSignal } = {}): Promise<SandboxInfo> {
    this.assertLive();
    const raw = await this.transport.unary<any, any>(
      "StopSandbox",
      { id: this.id },
      undefined,
      options.signal,
    );
    this.info = toSandboxInfo(raw);
    return this.info;
  }

  /**
   * Cold-boots a shut-down sandbox on its existing disks. It takes as long as a
   * create, since there is no memory image to restore, and the sandbox keeps
   * its id, name, address and published ports.
   */
  async boot(options: { signal?: AbortSignal } = {}): Promise<SandboxInfo> {
    this.assertLive();
    const raw = await this.transport.unary<any, any>(
      "StartSandbox",
      { id: this.id },
      undefined,
      options.signal,
    );
    this.info = toSandboxInfo(raw);
    await this.onResume?.(this);
    return this.info;
  }

  /**
   * Replaces the root disk, discarding everything written to it, while
   * keeping the sandbox's id, name, address and volumes. With `template` the
   * sandbox moves onto another template; a Kit is provisioned again on the
   * new disk with the recorded inputs, as changed by `kit`.
   */
  async recreate(options: RecreateOptions = {}): Promise<SandboxInfo> {
    this.assertLive();
    const raw = await this.transport.unary<any, any>(
      "RecreateSandbox",
      {
        sandboxId: this.id,
        template: options.template ?? "",
        kit: toKitSpec(options.kit),
      },
      undefined,
      options.signal,
    );
    this.info = toSandboxInfo(raw);
    await this.onResume?.(this);
    return this.info;
  }

  /**
   * Every VM this sandbox has run, newest first.
   *
   * A sandbox outlives its VMs: {@link stop} ends one and {@link resume}
   * starts the next. The node keeps only the most recent sessions of each
   * sandbox, and drops them all when the sandbox is deleted.
   *
   * ```ts
   * const [current] = await sandbox.listSessions();
   * console.log(current.startedBy, current.startedAt);
   * ```
   */
  async listSessions(options: { signal?: AbortSignal } = {}): Promise<Session[]> {
    this.assertLive();
    const res = await this.transport.unary<any, any>(
      "ListSessions",
      { id: this.id },
      undefined,
      options.signal,
    );
    return (res.sessions ?? []).map(toSession);
  }

  /**
   * The VM the sandbox is running now, or `undefined` when it is stopped.
   *
   * The open session is the one {@link listSessions} reports with no
   * `endedAt`.
   *
   * ```ts
   * const session = await sandbox.currentSession();
   * if (session) console.log(session.startedBy, session.startedAt);
   * ```
   */
  async currentSession(
    options: { signal?: AbortSignal } = {},
  ): Promise<Session | undefined> {
    const sessions = await this.listSessions(options);
    return sessions.find((session) => !session.endedAt);
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
    this.assertLive();
    const raw = await this.transport.unary<any, any>(
      "ForkSandbox",
      toForkRequest(this.id, options),
      120_000,
      options.signal,
    );
    // A fork shares its parent's connection, released once both are done.
    const transport = this.owned ? this.transport.retain() : this.transport;
    return new Sandbox(
      transport,
      toSandboxInfo(raw),
      this.owned,
      this.autoResume,
      // A fork is the same sandbox again, so it runs commands with the same
      // environment this handle applies.
      this.env,
    );
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
  async move(options: MoveOptions = {}): Promise<SandboxInfo> {
    this.assertLive();
    const raw = await this.transport.unary<any, any>(
      "MoveSandbox",
      {
        ref: { id: this.id },
        nodeId: options.nodeId ?? "",
        nodeLabels: options.nodeLabels ?? {},
      },
      300_000,
      options.signal,
    );
    this.info = toSandboxInfo(raw);
    return this.info;
  }

  /**
   * Saves the sandbox's state as a snapshot object and keeps running.
   *
   * The guest is paused only long enough to write its state. Unlike the
   * sandbox's own stop state, which dies with it, a snapshot outlives its
   * source and can start any number of new sandboxes:
   *
   * ```ts
   * const snapshot = await prepared.snapshot({ expiration: 86_400 });
   * const worker = await Sandbox.create({ snapshot: snapshot.id });
   * ```
   */
  async snapshot(options: SnapshotOptions = {}): Promise<Snapshot> {
    this.assertLive();
    const raw = await this.transport.unary<any, any>(
      "CreateSnapshot",
      {
        ref: { id: this.id },
        expirationSecs: options.expiration ?? 0,
      },
      // Writing a memory image and copying a scratch disk; seconds, not
      // milliseconds, on a large guest.
      120_000,
      options.signal,
    );
    // The snapshot shares this handle's connection, released once both are
    // done.
    return Snapshot.adopt(
      this.owned ? this.transport.retain() : this.transport,
      raw,
    );
  }

  /**
   * Destroys the sandbox and everything in it. The handle is inert
   * afterwards: every later call throws rather than failing obscurely against
   * an id that is no longer anywhere.
   */
  async delete(options: { signal?: AbortSignal } = {}): Promise<void> {
    this.assertLive();
    try {
      await this.transport.unary(
        "DeleteSandbox",
        { id: this.id },
        undefined,
        options.signal,
      );
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

/** Builds a `ForkSandboxRequest`. An omitted policy inherits the source's. */
function toForkRequest(source: string, options: ForkOptions): any {
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
        network:
          network === undefined
            ? undefined
            : toNetworkPolicy(resolveNetwork(network)),
        networks: toNetworks(options.networks),
        // Each section is inherited on its own, so overriding one does not
        // strip the others off the child.
        exec: toExecPolicy(options.exec),
        fs: toFsPolicy(options.fs),
      };
  return {
    ref: { id: source },
    sandboxId: options.sandboxId ?? options.id ?? "",
    name: options.name ?? "",
    policy,
    nodeLabels: options.nodeLabels ?? {},
  };
}

function toShare(raw: any): Share {
  return {
    address: raw.address ?? "",
    ports: (raw.ports ?? []).map((p: any) => Number(p)),
    allowedClients: raw.allowedClients ?? [],
    createdAt: raw.createdAt ?? "",
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
 * A connection to a burrow control plane, for listing or reattaching to
 * sandboxes over one channel. {@link Sandbox.create} is the shortcut when you
 * only need one.
 */
export class Burrow {
  private readonly transport: Transport;

  constructor(options: TransportOptions = {}) {
    this.transport = new Transport(options);
  }

  async health(): Promise<{ version: string }> {
    const res = await this.transport.unary<any, any>("Health", {});
    return { version: res.version ?? "" };
  }

  /**
   * Reads the egress audit trail, newest first.
   *
   * Records cover both connection attempts and DNS lookups, so an attempt is
   * visible even when the policy blocked it.
   */
  async audit(query: AuditQuery = {}): Promise<AuditEvent[]> {
    const events: AuditEvent[] = [];
    for await (const raw of this.transport.serverStream<any, any>("QueryAudit", {
      sandboxId: query.sandboxId ?? "",
      isDeniedOnly: query.deniedOnly ?? false,
      since: query.since ?? "",
      limit: query.limit ?? 0,
    })) {
      events.push({
        at: raw.at,
        sandboxId: raw.sandboxId,
        sourceIp: raw.sourceIp,
        destination: raw.destination,
        host: raw.host ?? "",
        port: Number(raw.port ?? 0),
        allowed: Boolean(raw.isAllowed),
        reason: raw.reason ?? "",
        bytesSent: Number(raw.bytesSent ?? 0),
        bytesReceived: Number(raw.bytesReceived ?? 0),
        nodeId: raw.nodeId ?? "",
      });
    }
    return events;
  }

  /**
   * Reads the fleet's lifecycle log, oldest first.
   *
   * Without `follow` the iterator ends after the replay. With it, the stream
   * stays open and yields events as they happen until `signal` aborts or the
   * loop breaks. Keep the last `seq` seen to resume after a disconnect.
   *
   * ```ts
   * for await (const event of burrow.events({ sandbox: "build-482", follow: true })) {
   *   console.log(event.seq, event.type, event.detail);
   * }
   * ```
   */
  async *events(options: EventsOptions = {}): AsyncGenerator<LifecycleEvent> {
    for await (const raw of this.transport.serverStream<any, any>(
      "TailEvents",
      {
        afterSeq: options.after ?? 0,
        sandbox: options.sandbox ?? "",
        isFollow: options.follow ?? false,
        limit: options.limit ?? 0,
      },
      // A follow outlives any request deadline.
      options.follow ? Infinity : undefined,
      options.signal,
    )) {
      yield {
        seq: Number(raw.seq ?? 0),
        nodeId: raw.nodeId ?? "",
        nodeSeq: Number(raw.nodeSeq ?? 0),
        atUnixMs: Number(raw.atUnixMs ?? 0),
        sandboxId: raw.sandboxId ?? "",
        type: raw.type ?? "",
        state: stateOf(raw.state),
        detail: raw.detail ?? "",
        template: raw.template ?? "",
        metadata: raw.metadata ?? {},
        cpuUsageUsec: Number(raw.cpuUsageUsec ?? 0),
        rxBytes: Number(raw.rxBytes ?? 0),
        txBytes: Number(raw.txBytes ?? 0),
        vcpus: Number(raw.vcpus ?? 0),
        memoryMib: Number(raw.memMib ?? 0),
      };
    }
  }

  /** Stops (or resumes) placing new sandboxes on a node. */
  async drainNode(
    nodeId: string,
    options: { drain?: boolean; suspendSandboxes?: boolean } = {},
  ): Promise<{ suspended: number }> {
    const res = await this.transport.unary<any, any>("DrainNode", {
      nodeId,
      isDraining: options.drain ?? true,
      suspendSandboxes: options.suspendSandboxes ?? false,
    });
    return { suspended: Number(res.suspended ?? 0) };
  }

  /**
   * Stores a credential that Sandbox Kits ask for by service name. The value
   * stays on the node and is injected into matching requests by the egress
   * proxy, so a guest never holds it. `name` is lowercase kebab-case, the
   * `service` a Kit credential names.
   */
  async setSecret(name: string, value: string): Promise<void> {
    await this.transport.unary<any, any>("SetSecret", { name, value });
  }

  /** Names of the stored secrets. Values are never returned. */
  async listSecrets(): Promise<string[]> {
    const res = await this.transport.unary<any, any>("ListSecrets", {});
    return [...(res.names ?? [])];
  }

  async deleteSecret(name: string): Promise<void> {
    await this.transport.unary<any, any>("DeleteSecret", { name });
  }

  async nodes(): Promise<NodeInfo[]> {
    const res = await this.transport.unary<any, any>("ListNodes", {});
    return (res.nodes ?? []).map((n: any) => ({
      id: n.info?.id ?? "",
      address: n.info?.address ?? "",
      hostname: n.info?.hostname ?? "",
      totalVcpus: Number(n.info?.totalVcpus ?? 0),
      totalMemoryMib: Number(n.info?.totalMemMib ?? 0),
      freeMemoryMib: Number(n.status?.freeMemMib ?? 0),
      runningSandboxes: Number(n.status?.runningSandboxes ?? 0),
      healthy: Boolean(n.isHealthy),
      draining: Boolean(n.status?.isDraining),
      labels: n.info?.labels ?? {},
      arch: n.info?.arch ?? "",
      firecrackerVersion: n.info?.firecrackerVersion ?? "",
    }));
  }

  close(): void {
    this.transport.close();
  }

  [Symbol.dispose](): void {
    this.close();
  }
}
