import { Buffer } from "node:buffer";
import { createWriteStream } from "node:fs";
import { mkdir } from "node:fs/promises";
import { dirname, resolve as resolvePath } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

import { BurrowError, CommandFailedError } from "./errors.js";
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
  CommandResult,
  CreateOptions,
  DetachedCommand,
  DirEntry,
  DownloadFileOptions,
  FileRef,
  FileWrite,
  FinishedCommand,
  ForkOptions,
  ForkSourceOptions,
  GetOptions,
  GetOrCreateOptions,
  GuestGroup,
  GuestUser,
  ListOptions,
  NodeInfo,
  OutputChunk,
  PortMapping,
  Share,
  ShareOptions,
  RunCommandOptions,
  RunCommandParams,
  RunOptions,
  SandboxInfo,
  SandboxState,
  SandboxStatus,
  Session,
  SessionEnd,
  SessionStart,
  UpdateOptions,
  Usage,
  WatchEvent,
  Watcher,
  WatchOptions,
} from "./types.js";

function toSandboxInfo(raw: any): SandboxInfo {
  const tags = raw.metadata ?? {};
  return {
    id: raw.id,
    name: raw.name ?? "",
    nodeId: raw.nodeId ?? "",
    template: raw.template ?? "",
    state: stateOf(raw.state),
    createdAt: raw.createdAt ?? "",
    guestIp: raw.guestIp ?? "",
    tags,
    metadata: tags,
    policy: fromPolicy(raw.policy),
    unreachable: raw.unreachable ?? false,
    usage: {
      // 64-bit on the wire, but nothing a sandbox consumes reaches the range
      // where handing them over as numbers costs precision.
      cpuUsageUsec: Number(raw.cpuUsageUsec ?? 0),
      rxBytes: Number(raw.rxBytes ?? 0),
      txBytes: Number(raw.txBytes ?? 0),
    },
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
    "stopping",
    "destroyed",
    "failed",
  ];
  return (known as string[]).includes(name) ? (name as SandboxState) : "unknown";
}

/** Builds a `CreateSandboxRequest` from the SDK's flatter options. */
function toCreateRequest(options: CreateOptions): any {
  const network = resolveNetwork(options.network ?? options.networkPolicy, {
    allowDomains: options.allowDomains,
    allowCidrs: options.allowCidrs,
  });
  const resources = options.resources ?? {
    vcpus: options.vcpus,
    memoryMib: options.memoryMib,
  };
  // A snapshot carries its own template, and one that disagrees is an error,
  // so nothing is sent as if the caller had asked for it.
  const template = options.template ?? options.image ?? "";
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
    metadata: options.tags ?? options.metadata ?? {},
    nodeLabels: options.nodeLabels ?? {},
  };
}

/** The five-state view of a sandbox's lifecycle. */
function statusOf(state: SandboxState): SandboxStatus {
  switch (state) {
    case "creating":
      return "pending";
    case "running":
      return "running";
    case "stopping":
      return "stopping";
    // All three are "not going to run anything until something is done".
    case "paused":
    case "suspended":
    case "destroyed":
      return "stopped";
    // `failed`, and any state a newer server reports that this client has no
    // name for.
    default:
      return "failed";
  }
}

/**
 * Bytes per uploaded chunk, matching HTTP/2's default flow-control window.
 * Larger chunks showed no measurable gain: a message bigger than the window
 * stalls for WINDOW_UPDATE round trips rather than pipelining.
 */
const UPLOAD_CHUNK = 64 * 1024;

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
   *   onCreate: (s) => s.writeFiles([{ path: "/work/app.py", content: src }]),
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
        if (options.resume && sandbox.status === "stopped") {
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

  /** Reattaches to an existing sandbox by id. Alias of {@link Sandbox.get}. */
  static connect(id: string, options: TransportOptions = {}): Promise<Sandbox> {
    return Sandbox.get({ ...options, id });
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

  /**
   * Creates a sandbox from another's current state.
   *
   * The source keeps running; a running source's state is written first, so the
   * child starts from its state as of the call.
   */
  static async fork(
    options: ForkSourceOptions & TransportOptions,
  ): Promise<Sandbox> {
    const transport = new Transport(options);
    try {
      const raw = await transport.unary<any, any>(
        "ForkSandbox",
        toForkRequest(options.source, options),
        options.timeoutMs ?? 120_000,
        options.signal,
      );
      return new Sandbox(transport, toSandboxInfo(raw), true);
    } catch (err) {
      transport.close();
      throw err;
    }
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

  /** The five-state view of {@link state}. Suspended reads as `stopped`. */
  get status(): SandboxStatus {
    return statusOf(this.info.state);
  }

  get template(): string {
    return this.info.template;
  }

  /** The template, under the name an image-shaped SDK uses. */
  get image(): string {
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

  get metadata(): Record<string, string> {
    return this.info.metadata;
  }

  get vcpus(): number {
    return this.info.policy.resources.vcpus;
  }

  get memory(): number {
    return this.info.policy.resources.memoryMib;
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

  /** The egress policy in force, with injected header values redacted. */
  get networkPolicy() {
    return this.info.policy.network;
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
   * Runs a command and returns once it exits.
   *
   * ```ts
   * const install = await sandbox.runCommand("pip", ["install", "cowsay"]);
   * console.log(install.exitCode, install.stdout());
   * ```
   *
   * A bare string goes through `/bin/sh -c`, so pipes and redirection work.
   * Once `args` are given the command is passed to execve directly, with no
   * shell involved.
   */
  async runCommand(
    command: string,
    args?: string[],
    options?: RunCommandOptions,
  ): Promise<FinishedCommand>;
  async runCommand(
    params: RunCommandParams & { detached: true },
  ): Promise<DetachedCommand>;
  async runCommand(params: RunCommandParams): Promise<FinishedCommand>;
  async runCommand(
    first: string | RunCommandParams,
    args?: string[],
    options: RunCommandOptions = {},
  ): Promise<FinishedCommand | DetachedCommand> {
    const params: RunCommandParams =
      typeof first === "string"
        ? { ...options, cmd: first, args }
        : { ...first };

    // `stdout`/`stderr` are Writables, and the callbacks are the same thing
    // one chunk at a time, so one is expressed in terms of the other.
    if (params.stdout) {
      const sink = params.stdout;
      const previous = params.onStdout;
      params.onStdout = (chunk) => {
        previous?.(chunk);
        sink.write(chunk);
      };
    }
    if (params.stderr) {
      const sink = params.stderr;
      const previous = params.onStderr;
      params.onStderr = (chunk) => {
        previous?.(chunk);
        sink.write(chunk);
      };
    }

    const argv = params.args ?? [];
    const shell = params.shell ?? argv.length === 0;
    const command = shell
      ? argv.length
        ? [params.cmd, ...argv].join(" ")
        : params.cmd
      : [params.cmd, ...argv];

    if (params.detached) return this.spawn(command, params);

    const result = await this.exec(command, params);
    return toFinished(result);
  }

  /**
   * Starts a command and returns a handle without waiting for it.
   *
   * Used by `runCommand({ detached: true })`. The stream is started eagerly, so
   * output produced before you read `logs()` is buffered rather than lost.
   */
  private async spawn(
    command: string | string[],
    options: RunCommandOptions,
  ): Promise<DetachedCommand> {
    const { output, commandId } = this.startExec(command, options, true);
    const sandboxId = this.id;
    // Awaited: a handle whose `cmdId` did not yet name the command is one
    // another process could not use.
    const cmdId = await commandId;

    const chunks = (async function* () {
      for await (const chunk of output) {
        if (chunk.type === "stdout") options.onStdout?.(chunk.data);
        else if (chunk.type === "stderr") options.onStderr?.(chunk.data);
        yield chunk;
      }
    })();

    // `logs()` and `wait()` drain the same iterator, so only the first of them
    // gets anything; the second is refused rather than left empty.
    let taken = false;
    const take = () => {
      if (taken) {
        throw new BurrowError(
          "this command's output has already been consumed",
          "failed_precondition",
        );
      }
      taken = true;
      return chunks;
    };

    return {
      sandboxId,
      cmdId,
      logs: () => take(),
      // The same RPC `getCommand(...).kill()` uses: the command lives in the
      // sandbox, not on this stream.
      kill: (signal = 9) => this.killCommand(cmdId, signal),
      killed: (signal = 9) => this.signalCommand(cmdId, signal),
      wait: () => collect(take()),
    };
  }

  /**
   * Runs a command and returns once it exits.
   *
   * A string is run through `/bin/sh -c`, so pipes and redirection work; an
   * array is passed to execve directly, with no shell involved.
   *
   * ```ts
   * await sandbox.exec("pip install cowsay");
   * await sandbox.exec(["python3", "-c", "print(1 + 1)"]);
   * ```
   */
  async exec(
    command: string | string[],
    options: RunCommandOptions = {},
  ): Promise<CommandResult> {
    const run = async (): Promise<CommandResult> => {
      let stdout = "";
      let stderr = "";
      let exitCode = 0;

      // Auto-resume is handled here rather than in `execStream`: a stream that
      // has already yielded cannot be restarted without replaying output.
      for await (const chunk of this.execStream(command, {
        ...options,
        autoResume: false,
      })) {
        switch (chunk.type) {
          case "stdout":
            stdout += chunk.data;
            options.onStdout?.(chunk.data);
            break;
          case "stderr":
            stderr += chunk.data;
            options.onStderr?.(chunk.data);
            break;
          case "exit":
            exitCode = chunk.exitCode;
            break;
        }
      }
      return { stdout, stderr, exitCode, success: exitCode === 0 };
    };

    const result = await this.withResume(run, options.autoResume ?? this.autoResume);
    if (options.check && !result.success) {
      throw new CommandFailedError(
        Array.isArray(command) ? command.join(" ") : command,
        result.exitCode,
        result.stdout,
        result.stderr,
      );
    }
    return result;
  }

  /**
   * Runs a command, yielding output as it is produced.
   *
   * ```ts
   * for await (const chunk of sandbox.execStream("npm install")) {
   *   if (chunk.type === "stdout") process.stdout.write(chunk.data);
   * }
   * ```
   */
  async *execStream(
    command: string | string[],
    options: RunCommandOptions = {},
  ): AsyncGenerator<OutputChunk> {
    yield* this.startExec(command, options).output;
  }

  /** Starts a command, returning its output and the id the guest gave it. */
  private startExec(
    command: string | string[],
    options: RunCommandOptions,
    keepOpen = false,
  ): {
    output: AsyncGenerator<OutputChunk>;
    /** The id the guest gave the command; empty if the stream never named it. */
    commandId: Promise<string>;
  } {
    this.assertLive();
    const cmd = Array.isArray(command) ? command : ["/bin/sh", "-c", command];

    const start = {
      start: {
        sandboxId: this.id,
        cmd,
        // A per-command variable wins over the handle's defaults, so one call
        // can override what every other call inherits.
        env: { ...this.env, ...(options.env ?? {}) },
        cwd: options.cwd ?? "",
        pty: options.pty ?? false,
        rows: options.rows ?? 24,
        cols: options.cols ?? 80,
        user: options.user ?? this.defaultUser,
      },
    };

    const { call, output } = this.transport.openStream<any>(
      "Exec",
      start,
      options.timeoutMs,
      options.signal,
    );
    // Either way the command sees an empty stdin: `stdinEof` closes the
    // child's stdin without closing the request side, which a detached command
    // keeps open.
    if (keepOpen) call.write({ stdinEof: true });
    else call.end();

    // The guest names the command before anything else. Pulled here rather
    // than inside the generator below, which nothing iterates until the caller
    // asks for output: a detached command's id has to exist before then.
    const first = output.next();
    const commandId = first.then((result) =>
      !result.done && result.value?.output === "commandId"
        ? String(result.value.commandId ?? "")
        : // A stream that failed or ended before naming anything. The command
          // may still have run; there is simply no id to come back to it with.
          "",
    );

    const chunks = (async function* (): AsyncGenerator<OutputChunk> {
      const opening = await first;
      if (opening.done) return;
      // An older agent starts straight in on output, with no id at all.
      if (opening.value?.output !== "commandId") yield* toChunk(opening.value);
      for await (const msg of output) {
        // Only ever the first message, but an agent that repeated it must not
        // put an empty chunk into the caller's stream.
        if (msg.output === "commandId") continue;
        yield* toChunk(msg);
      }
    })();

    return { output: chunks, commandId };
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
   * Reattaches to a command by id, from anywhere.
   *
   * ```ts
   * const command = await sandbox.getCommand(cmdId);
   * for await (const chunk of command.logs()) process.stdout.write(chunk.data);
   * ```
   *
   * The command need not have been started by this process: it lives in the
   * sandbox. `logs()` replays what the guest still holds and then follows the
   * command live, and several readers may do that at once. Throws `not_found`
   * when the id names nothing, an evicted command included.
   */
  async getCommand(
    cmdId: string,
    options: { signal?: AbortSignal } = {},
  ): Promise<DetachedCommand & { info: CommandInfo }> {
    this.assertLive();
    // Read first, so a bad id fails here rather than on the first `logs()`.
    const raw = await this.transport.unary<any, any>(
      "GetCommand",
      { sandboxId: this.id, commandId: cmdId },
      undefined,
      options.signal,
    );
    return { ...this.commandHandle(cmdId), info: toCommandInfo(raw) };
  }

  /**
   * A handle onto a command that already exists in the sandbox. Every method
   * opens its own call, so `logs()` and `wait()` do not compete for one stream
   * the way a locally started detached command's do.
   */
  private commandHandle(cmdId: string): DetachedCommand {
    const attach = (): AsyncGenerator<OutputChunk> => {
      const stream = this.transport.serverStream<any, any>(
        "AttachCommand",
        { sandboxId: this.id, commandId: cmdId },
        // A command outlives any request deadline.
        Infinity,
      );
      return (async function* () {
        for await (const msg of stream) yield* toChunk(msg);
      })();
    };

    return {
      sandboxId: this.id,
      cmdId,
      logs: attach,
      kill: (signal = 9) => this.killCommand(cmdId, signal),
      killed: (signal = 9) => this.signalCommand(cmdId, signal),
      wait: () => collect(attach()),
    };
  }

  /**
   * Signals a command and resolves once the node has delivered it. The
   * awaitable half of `kill()`: every refusal is visible here.
   */
  private async signalCommand(cmdId: string, signal: number): Promise<void> {
    await this.transport.unary("SignalCommand", {
      sandboxId: this.id,
      commandId: cmdId,
      signal,
    });
  }

  /**
   * Fire-and-forget signal, so `kill()` stays synchronous.
   *
   * Only one outcome is swallowed: the command had already exited, which is
   * what kill wanted anyway. Every other failure is left to reject, because a
   * sandbox tightened to deny exec refuses signals too, and silently doing
   * nothing there is indistinguishable from having killed it. Await
   * `killed()` to handle those rather than take an unhandled rejection.
   */
  private killCommand(cmdId: string, signal: number): void {
    void this.signalCommand(cmdId, signal).catch((err: unknown) => {
      if (err instanceof BurrowError && err.isAlreadyExited) return;
      throw err;
    });
  }

  /**
   * Creates a guest user with a private home directory.
   *
   * ```ts
   * const alice = await sandbox.createUser("alice");
   * await sandbox.runCommand({ cmd: "whoami", user: alice.username });
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
   * A handle onto the same sandbox whose commands run as `name`.
   *
   * ```ts
   * const alice = sandbox.asUser("alice");
   * await alice.runCommand("touch ~/notes.txt");
   * ```
   *
   * Commands, terminals and `mkDir` run as the user, and `writeFile` hands
   * what it wrote to them. Reads are not confined: `readFile` and `listDir`
   * are served by the guest agent as root, so a user handle can still read a
   * file its user could not. The user has to exist already.
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

  /** Alias of {@link exec}, for parity with SDKs that group commands. */
  get commands(): { run: Sandbox["exec"]; stream: Sandbox["execStream"] } {
    return {
      run: this.exec.bind(this),
      stream: this.execStream.bind(this),
    };
  }

  /**
   * Opens an interactive shell with a pty, for when input arrives over time
   * (a browser terminal, an agent driving a REPL). For a command that runs to
   * completion, use {@link runCommand}.
   */
  terminal(options: TerminalOptions = {}): Terminal {
    this.assertLive();
    return new Terminal(this.transport, this.id, options);
  }

  /**
   * Writes files, creating parent directories as needed.
   *
   * ```ts
   * await sandbox.writeFiles([
   *   { path: "/work/app.py", content: "print('hi')\n" },
   *   { path: "/work/run.sh", content: "python3 app.py\n", mode: 0o755 },
   * ]);
   * ```
   */
  async writeFiles(
    files: ReadonlyArray<FileWrite>,
    options: { signal?: AbortSignal } = {},
  ): Promise<void> {
    for (const file of files) {
      const content = file.content ?? file.contents ?? "";
      await this.writeFile(file.path, content, {
        mode: file.mode,
        signal: options.signal,
      });
    }
  }

  /** Writes a single file, creating parent directories as needed. */
  async writeFile(
    path: string,
    contents: string | Uint8Array,
    options: { mode?: number; signal?: AbortSignal } = {},
  ): Promise<number> {
    this.assertLive();
    const bytes =
      typeof contents === "string" ? Buffer.from(contents, "utf8") : contents;

    const chunks: any[] = [];
    for (let offset = 0; offset < bytes.length || chunks.length === 0; ) {
      const end = Math.min(offset + UPLOAD_CHUNK, bytes.length);
      chunks.push({
        // Only the first chunk names the destination.
        sandboxId: chunks.length === 0 ? this.id : "",
        path: chunks.length === 0 ? path : "",
        mode: chunks.length === 0 ? (options.mode ?? 0) : 0,
        data: bytes.subarray(offset, end),
      });
      offset = end;
    }

    const res = await this.withResume(() =>
      this.transport.pipeUnary<any, any>(
        "UploadFile",
        chunks,
        undefined,
        options.signal,
      ),
    );
    // The agent writes as root, so a handle from `asUser` has to hand the
    // file over or the user could not touch what it wrote.
    if (this.defaultUser) {
      // `user: ""` is root: the user being handed the file cannot be the one
      // handing it over.
      await this.exec(["/bin/chown", this.defaultUser, "--", path], {
        user: "",
      });
    }
    return Number(res.bytesWritten ?? 0);
  }

  /**
   * Reads a file.
   *
   * `readFile("/work/out.txt")` returns the contents as a string.
   * `readFile({ path })` returns a readable stream, or `null` when the file
   * does not exist, which is the shape a large download wants.
   */
  async readFile(path: string): Promise<string>;
  async readFile(params: FileRef): Promise<Readable | null>;
  async readFile(target: string | FileRef): Promise<string | Readable | null> {
    if (typeof target === "string") {
      return Buffer.from(await this.readFileBytes(target)).toString("utf8");
    }
    const stream = await this.openFile(target);
    return stream && Readable.from(stream);
  }

  /** Reads a file as a `Buffer`, or `null` when it does not exist. */
  async readFileToBuffer(target: string | FileRef): Promise<Buffer | null> {
    const params: FileRef =
      typeof target === "string" ? { path: target } : target;
    const stream = await this.openFile(params);
    if (!stream) return null;
    const parts: Buffer[] = [];
    for await (const chunk of stream) parts.push(chunk);
    return Buffer.concat(parts);
  }

  /**
   * Copies a file out of the sandbox onto the local filesystem.
   *
   * Returns the absolute path it was written to, or `null` when the sandbox
   * has no such file. Parent directories are created unless you say otherwise.
   *
   * ```ts
   * const path = await sandbox.downloadFile("/work/out.txt", "./out.txt");
   * ```
   */
  async downloadFile(
    src: string,
    dst: string,
    options: DownloadFileOptions = {},
  ): Promise<string | null> {
    const stream = await this.openFile({ path: src, signal: options.signal });
    if (!stream) return null;

    const destination = resolvePath(dst);
    if (options.mkdirRecursive !== false) {
      await mkdir(dirname(destination), { recursive: true });
    }
    // Streamed rather than buffered: a download is exactly the case where the
    // file is too big to want in memory.
    await pipeline(Readable.from(stream), createWriteStream(destination));
    return destination;
  }

  /** Reads a file as raw bytes. Throws when it does not exist. */
  async readFileBytes(
    path: string,
    options: { signal?: AbortSignal } = {},
  ): Promise<Uint8Array> {
    this.assertLive();
    const parts: Buffer[] = [];
    await this.withResume(async () => {
      parts.length = 0;
      for await (const chunk of this.transport.serverStream<any, any>(
        "DownloadFile",
        { sandboxId: this.id, path },
        undefined,
        options.signal,
      )) {
        if (chunk.data?.length) parts.push(Buffer.from(chunk.data));
      }
    });
    return Buffer.concat(parts);
  }

  /**
   * Starts a download, returning `null` if the file is missing.
   *
   * The first chunk is pulled eagerly because that is when the server reports
   * a missing file, and a `null` return has to be decided up front.
   */
  private async openFile(
    params: FileRef,
  ): Promise<AsyncGenerator<Buffer> | null> {
    this.assertLive();
    const open = async () => {
      const source = this.transport.serverStream<any, any>(
        "DownloadFile",
        { sandboxId: this.id, path: params.path },
        undefined,
        params.signal,
      );
      const first = await source.next();
      return { source, first };
    };

    let started: Awaited<ReturnType<typeof open>>;
    try {
      started = await this.withResume(open);
    } catch (err) {
      if (err instanceof BurrowError && err.code === "not_found") return null;
      throw err;
    }

    const { source, first } = started;
    return (async function* () {
      if (!first.done && first.value?.data?.length) {
        yield Buffer.from(first.value.data);
      }
      for await (const chunk of source) {
        if (chunk.data?.length) yield Buffer.from(chunk.data);
      }
    })();
  }

  /** Lists a directory. */
  async listDir(
    path: string,
    options: { signal?: AbortSignal } = {},
  ): Promise<DirEntry[]> {
    this.assertLive();
    const res = await this.withResume(() =>
      this.transport.unary<any, any>(
        "ListDir",
        { sandboxId: this.id, path },
        undefined,
        options.signal,
      ),
    );
    return (res.entries ?? []).map((e: any) => ({
      name: e.name,
      isDir: Boolean(e.isDir),
      size: Number(e.size ?? 0),
      mode: Number(e.mode ?? 0),
    }));
  }

  /**
   * Creates a directory.
   *
   * There is no mkdir RPC, so this runs `mkdir -p` in the sandbox: it costs
   * one exec and fails the way a command does rather than the way an RPC does.
   */
  async mkDir(
    path: string,
    options: { recursive?: boolean } = {},
  ): Promise<void> {
    const flag = options.recursive === false ? "" : "-p ";
    const res = await this.exec(`mkdir ${flag}${shellQuote(path)}`);
    if (!res.success) {
      throw new BurrowError(
        `mkdir ${path} failed: ${res.stderr.trim()}`,
        "internal",
      );
    }
  }

  /** Alias of {@link mkDir}, kept for callers written against it. */
  mkdir(path: string, options: { recursive?: boolean } = {}): Promise<void> {
    return this.mkDir(path, options);
  }

  /** File helpers grouped, for parity with SDKs that namespace them. */
  get fs() {
    return {
      readFile: this.readFile.bind(this) as Sandbox["readFile"],
      readFileToBuffer: this.readFileToBuffer.bind(this),
      writeFile: this.writeFile.bind(this),
      writeFiles: this.writeFiles.bind(this),
      readDir: this.listDir.bind(this),
      mkDir: this.mkDir.bind(this),
    };
  }

  /** The same helpers under the names earlier versions used. */
  get files() {
    return {
      read: this.readFile.bind(this) as Sandbox["readFile"],
      readBytes: this.readFileBytes.bind(this),
      write: this.writeFile.bind(this),
      list: this.listDir.bind(this),
      mkdir: this.mkDir.bind(this),
    };
  }

  /**
   * Watches a directory for changes.
   *
   * The guest polls and reports differences, so an edit is seen within roughly
   * `intervalMs` and a file created and removed between two scans is not seen
   * at all.
   *
   * ```ts
   * const watcher = await sandbox.watch("/work/src", {
   *   recursive: true,
   *   onEvent: (e) => console.log(e.type, e.path),
   * });
   * // ...later
   * watcher.stop();
   * ```
   */
  async watch(path: string, options: WatchOptions = {}): Promise<Watcher> {
    this.assertLive();
    const stream = this.transport.serverStream<any, any>(
      "Watch",
      {
        sandboxId: this.id,
        path,
        recursive: options.recursive ?? false,
        intervalMs: options.intervalMs ?? 0,
      },
      // Watches outlive any request deadline.
      Infinity,
    );

    let stopped = false;
    const events: AsyncGenerator<WatchEvent> = (async function* () {
      try {
        for await (const raw of stream) {
          if (stopped) return;
          yield {
            type: raw.type as WatchEvent["type"],
            path: raw.path,
            isDir: Boolean(raw.isDir),
          };
        }
      } catch (err) {
        if (!stopped) throw err;
      }
    })();

    // Callback style drives the iterator in the background; iterator style
    // hands it to the caller. Both stop the same way.
    if (options.onEvent) {
      void (async () => {
        try {
          for await (const event of events) options.onEvent!(event);
        } catch (err) {
          options.onError?.(err as Error);
        }
      })();
    }

    return {
      stop() {
        stopped = true;
        void events.return(undefined as never);
      },
      [Symbol.asyncIterator]: () => events,
    };
  }

  /**
   * Publishes a port from inside the sandbox on its node's address.
   *
   * ```ts
   * const { url } = await sandbox.exposePort(8000);
   * ```
   */
  async exposePort(
    guestPort: number,
    hostPort?: number | { hostPort?: number; signal?: AbortSignal },
  ): Promise<PortMapping> {
    this.assertLive();
    const options =
      typeof hostPort === "number" ? { hostPort } : (hostPort ?? {});
    const res = await this.transport.unary<any, any>(
      "ExposePort",
      { sandboxId: this.id, guestPort, hostPort: options.hostPort ?? 0 },
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
   * everywhere with `allUdp`.
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
        rotate: options.rotate ?? false,
        proxyProtocol: options.proxyProtocol ?? false,
        udpPorts: options.udpPorts ?? [],
        allUdp: options.allUdp ?? false,
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
   * Updates tags, the network policy, the access policy, or any combination.
   *
   * Each section named is replaced wholesale rather than merged, so one call
   * is enough to lock a sandbox down or to retag it, and a section not named
   * is left alone. The machine shape is not updatable: a restore takes it from
   * the snapshot.
   *
   * ```ts
   * await sandbox.update({
   *   tags: { owner: "ci", run: "482" },
   *   networkPolicy: { mode: "allowlist", allowDomains: ["api.github.com"] },
   *   exec: { allowExec: false },
   * });
   * ```
   */
  async update(options: UpdateOptions): Promise<SandboxInfo> {
    const network = options.networkPolicy ?? options.network;
    if (options.tags) {
      await this.updateTags(options.tags, { signal: options.signal });
    }
    if (network !== undefined) {
      await this.updateNetworkPolicy(network, { signal: options.signal });
    }
    if (options.exec !== undefined || options.fs !== undefined) {
      await this.updateAccessPolicy(options, { signal: options.signal });
    }
    if (
      options.maxLifetimeSecs !== undefined ||
      options.idleSuspendSecs !== undefined ||
      options.suspendedTtlSecs !== undefined
    ) {
      await this.updateResources(options);
    }
    return this.info;
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

  /**
   * Gives the sandbox `ms` more milliseconds of life, from when it was created.
   *
   * The familiar spelling of `update({ maxLifetimeSecs })`. Burrow measures a
   * lifetime from creation rather than from now, so this sets a total rather
   * than adding to what is left: pass the whole budget.
   *
   * ```ts
   * await sandbox.extendTimeout(60 * 60 * 1000); // an hour from its creation
   * ```
   */
  async extendTimeout(
    ms: number,
    options: { signal?: AbortSignal } = {},
  ): Promise<SandboxInfo> {
    return this.updateResources({
      maxLifetimeSecs: Math.ceil(ms / 1000),
      signal: options.signal,
    });
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

  /** The same thing under its original name. */
  pause(options: { signal?: AbortSignal } = {}): Promise<SandboxInfo> {
    return this.stop(options);
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

  /**
   * Destroys the sandbox.
   *
   * @deprecated Use {@link delete}. Note that {@link stop} suspends rather than
   * destroys, so it is not the replacement.
   */
  kill(): Promise<void> {
    return this.delete();
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
  const network = options.networkPolicy ?? options.network;
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

/**
 * One `ExecOutput` message as the SDK's chunk, if it carries anything. Shared
 * by a running exec and a later attach. The oneof tag is checked rather than
 * the fields: proto defaults give every message an `exitCode` of 0 and empty
 * byte fields.
 */
function* toChunk(msg: any): Generator<OutputChunk> {
  if (msg.stdout?.length) {
    yield { type: "stdout", data: Buffer.from(msg.stdout).toString("utf8") };
  } else if (msg.stderr?.length) {
    yield { type: "stderr", data: Buffer.from(msg.stderr).toString("utf8") };
  } else if (msg.output === "exitCode") {
    yield { type: "exit", exitCode: msg.exitCode ?? 0 };
  }
}

/** Drains a command's output into the result a finished command reports. */
async function collect(
  chunks: AsyncIterable<OutputChunk>,
): Promise<FinishedCommand> {
  let stdout = "";
  let stderr = "";
  let exitCode = 0;
  for await (const chunk of chunks) {
    if (chunk.type === "stdout") stdout += chunk.data;
    else if (chunk.type === "stderr") stderr += chunk.data;
    else exitCode = chunk.exitCode;
  }
  return toFinished({ stdout, stderr, exitCode, success: exitCode === 0 });
}

function toFinished(result: CommandResult): FinishedCommand {
  return {
    exitCode: result.exitCode,
    success: result.success,
    stdout: () => result.stdout,
    stderr: () => result.stderr,
  };
}

function toShare(raw: any): Share {
  return {
    address: raw.address ?? "",
    ports: (raw.ports ?? []).map((p: any) => Number(p)),
    allowedClients: raw.allowedClients ?? [],
    proxyProtocol: Boolean(raw.proxyProtocol),
    createdAt: raw.createdAt ?? "",
    udpPorts: (raw.udpPorts ?? []).map((p: any) => Number(p)),
    allUdp: Boolean(raw.allUdp),
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
    url: `http://${address}`,
    // Empty unless the holding node's edge is serving, rather than a name
    // that resolves nowhere.
    edgeUrl: raw.edgeUrl || undefined,
  };
}

/** Quotes a path for `sh -c`. */
function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
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

  async create(options: CreateOptions = {}): Promise<Sandbox> {
    const raw = await this.transport.unary<any, any>(
      "CreateSandbox",
      toCreateRequest(options),
      options.timeoutMs ?? 120_000,
      options.signal,
    );
    return Sandbox.adopt(this.transport, raw);
  }

  /** Lists sandboxes, optionally filtered by one `"key=value"` tag. */
  async list(options: ListOptions = {}): Promise<SandboxInfo[]> {
    const res = await this.transport.unary<any, any>(
      "ListSandboxes",
      { tag: options.tag ?? "" },
      undefined,
      options.signal,
    );
    return (res.sandboxes ?? []).map(toSandboxInfo);
  }

  async get(id: string): Promise<Sandbox> {
    const raw = await this.transport.unary<any, any>("GetSandbox", { id });
    return Sandbox.adopt(this.transport, raw);
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
      deniedOnly: query.deniedOnly ?? false,
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
        allowed: Boolean(raw.allowed),
        reason: raw.reason ?? "",
        bytesSent: Number(raw.bytesSent ?? 0),
        bytesReceived: Number(raw.bytesReceived ?? 0),
        nodeId: raw.nodeId ?? "",
      });
    }
    return events;
  }

  /** Stops (or resumes) placing new sandboxes on a node. */
  async drainNode(
    nodeId: string,
    options: { drain?: boolean; suspendSandboxes?: boolean } = {},
  ): Promise<{ suspended: number }> {
    const res = await this.transport.unary<any, any>("DrainNode", {
      nodeId,
      drain: options.drain ?? true,
      suspendSandboxes: options.suspendSandboxes ?? false,
    });
    return { suspended: Number(res.suspended ?? 0) };
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
      healthy: Boolean(n.healthy),
      draining: Boolean(n.status?.draining),
      labels: n.info?.labels ?? {},
    }));
  }

  close(): void {
    this.transport.close();
  }

  [Symbol.dispose](): void {
    this.close();
  }
}
