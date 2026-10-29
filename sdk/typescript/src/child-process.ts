/**
 * `sandbox.childProcess`: Node's `child_process`, run in the guest.
 *
 * A command is an `Exec` stream, and a command started elsewhere is reached
 * with `Attach`; either way it surfaces as a `ChildProcess` that behaves like
 * Node's, so code written against `child_process` runs here unchanged.
 */

import { Buffer } from "node:buffer";
import { EventEmitter, type Abortable } from "node:events";
import { finished, Readable, Writable } from "node:stream";

import { BurrowError } from "./errors.js";
import { abortError, invalidArgValue, toPath } from "./fs.js";
import type { GuestLink } from "./guest.js";

/**
 * Linux's signal numbers. Not `os.constants.signals`, which are this
 * machine's: on macOS SIGUSR1 is 30, and the guest would read it as SIGPWR.
 */
const SIGNALS: Record<string, number> = {
  SIGHUP: 1,
  SIGINT: 2,
  SIGQUIT: 3,
  SIGILL: 4,
  SIGTRAP: 5,
  SIGABRT: 6,
  SIGIOT: 6,
  SIGBUS: 7,
  SIGFPE: 8,
  SIGKILL: 9,
  SIGUSR1: 10,
  SIGSEGV: 11,
  SIGUSR2: 12,
  SIGPIPE: 13,
  SIGALRM: 14,
  SIGTERM: 15,
  SIGSTKFLT: 16,
  SIGCHLD: 17,
  SIGCONT: 18,
  SIGSTOP: 19,
  SIGTSTP: 20,
  SIGTTIN: 21,
  SIGTTOU: 22,
  SIGURG: 23,
  SIGXCPU: 24,
  SIGXFSZ: 25,
  SIGVTALRM: 26,
  SIGPROF: 27,
  SIGWINCH: 28,
  SIGIO: 29,
  SIGPOLL: 29,
  SIGPWR: 30,
  SIGSYS: 31,
};

/** First name wins, so 6 reads as SIGABRT and 29 as SIGIO, as Node names them. */
const SIGNAL_NAMES = new Map<number, NodeJS.Signals>();
for (const [name, number] of Object.entries(SIGNALS)) {
  if (!SIGNAL_NAMES.has(number)) SIGNAL_NAMES.set(number, name as NodeJS.Signals);
}

function toSignal(signal: NodeJS.Signals | number): number {
  if (typeof signal === "number") return signal;
  const number = SIGNALS[signal];
  if (number === undefined) {
    throw Object.assign(new TypeError(`Unknown signal: ${signal}`), { code: "ERR_UNKNOWN_SIGNAL" });
  }
  return number;
}

type StdioMode = "pipe" | "ignore";

/** Options only Burrow has, on every way of starting a command. */
export interface BurrowCommandOptions {
  /**
   * Burrow only. Guest user to run as; defaults to the handle's, which is
   * root unless it came from {@link Sandbox.asUser}. The user has to exist,
   * and `HOME`, `USER`, `LOGNAME` and the default `cwd` follow it.
   */
  user?: string;
  /** Burrow only. Run under a pty, so the program sees a terminal. Its stderr arrives on stdout. */
  pty?: boolean;
  /** Burrow only. The pty's size; 24 by 80 when omitted. */
  rows?: number;
  cols?: number;
  /**
   * Burrow only. Rotate the command's output log on the node once a file
   * reaches this many bytes, as Docker's `--log-opt max-size`. Unset keeps
   * every byte, for a later {@link Sandbox.getCommand} to replay.
   */
  logMaxBytes?: number;
  /** Burrow only. Log files kept once rotating, as Docker's `--log-opt max-file`. */
  logMaxFiles?: number;
}

/**
 * `spawn`'s options, as Node's where the guest has an equivalent.
 *
 * `env` is laid over the guest's own environment and the handle's `env`,
 * not over this process's: nothing from here leaks into the sandbox.
 */
export interface SpawnOptions extends Abortable, BurrowCommandOptions {
  cwd?: string | URL;
  env?: NodeJS.ProcessEnv;
  /** `true` runs `command` with its args through `/bin/sh -c`; a string names the shell. */
  shell?: boolean | string;
  /** Kill with `killSignal` after this many milliseconds. */
  timeout?: number;
  killSignal?: NodeJS.Signals | number;
  /** `"pipe"` or `"ignore"`, for all three or each. `null` in the array is `"pipe"`. */
  stdio?: StdioMode | [StdioMode | null, StdioMode | null, StdioMode | null];
}

/** `exec`'s options, as Node's `ExecOptions`. */
export interface ExecCommandOptions extends Abortable, BurrowCommandOptions {
  cwd?: string | URL;
  env?: NodeJS.ProcessEnv;
  /** `"buffer"` or `null` resolves Buffers. Defaults to `"utf8"`. */
  encoding?: BufferEncoding | "buffer" | null;
  /** Defaults to `/bin/sh`. */
  shell?: string;
  timeout?: number;
  /** Bytes of stdout or stderr kept before the command is killed. Defaults to 1 MiB. */
  maxBuffer?: number;
  killSignal?: NodeJS.Signals | number;
}

/** `execFile`'s options, as Node's `ExecFileOptions`: no shell unless asked for. */
export interface ExecFileOptions extends Omit<ExecCommandOptions, "shell"> {
  shell?: boolean | string;
}

/** What `exec` and `execFile` resolve, with the child it started, as `util.promisify` gives them. */
export type PromiseWithChild<T> = Promise<T> & { child: ChildProcess };

/**
 * What `exec` and `execFile` reject with: Node's error for a failed command.
 * `code` is the exit code, `null` when a signal ended it.
 */
export interface ExecError extends Error {
  code?: number | string | null;
  killed?: boolean;
  signal?: NodeJS.Signals | null;
  cmd: string;
  stdout: string | Buffer;
  stderr: string | Buffer;
}

/** @internal How a {@link ChildProcess} reaches its command. */
interface Channel {
  /** `ExecOutput` messages, from the start or from the attach offset. */
  output: AsyncIterable<any>;
  input(message: { stdin: Uint8Array } | { isStdinEof: true }): void;
  signal(signal: number, cmdId: string | undefined): Promise<void>;
  /** Ends the request side, once nothing more will be sent. */
  end(): void;
}

/** @internal */
interface ChildInit {
  spawnfile: string;
  spawnargs: string[];
  stdio: [StdioMode, StdioMode, StdioMode];
  /** A command found by id already exists, so it has spawned before it is reached. */
  cmdId?: string;
  timeout?: number;
  killSignal?: NodeJS.Signals | number;
  signal?: AbortSignal;
}

/**
 * A command in the sandbox, as Node's `ChildProcess`.
 *
 * ```ts
 * const child = sandbox.childProcess.spawn("python3", ["-u", "train.py"]);
 * child.stdout.on("data", (chunk) => process.stdout.write(chunk));
 * child.on("close", (code, signal) => console.log("done", code, signal));
 * ```
 *
 * Events are Node's: `spawn` once the guest has started it, `exit` and then
 * `close` with `(code, signal)`, and `error`. A command a signal ended exits
 * with `code` null and `signal` named, as Node reports it. One more, Burrow's
 * own: `lost`, with a byte count, for output a rotated log no longer holds.
 *
 * The command lives in the sandbox, not in this object: it keeps running if
 * this process exits, and {@link Sandbox.getCommand} reaches it again by
 * {@link cmdId}.
 */
export class ChildProcess extends EventEmitter {
  readonly stdin: Writable | null;
  readonly stdout: Readable | null;
  readonly stderr: Readable | null;
  readonly stdio: [Writable | null, Readable | null, Readable | null];
  /** Always undefined: the guest's process id is not exposed. {@link cmdId} names the command. */
  readonly pid: undefined = undefined;
  /** Burrow only. The command's id in the sandbox, set by the time `spawn` fires. */
  cmdId: string | undefined;
  exitCode: number | null = null;
  signalCode: NodeJS.Signals | null = null;
  killed = false;
  readonly spawnfile: string;
  readonly spawnargs: string[];
  /** There is no IPC channel to a guest process. */
  readonly connected = false;

  private readonly channel: Channel;
  /** Settles once the command exists, which input and signals wait for. */
  private readonly started: Promise<void>;
  private markStarted!: () => void;
  private failStart!: (err: unknown) => void;
  private hasStarted = false;
  private timer?: NodeJS.Timeout;
  private unbindAbort = () => {};

  /** @internal */
  constructor(channel: Channel, init: ChildInit) {
    super();
    this.channel = channel;
    this.spawnfile = init.spawnfile;
    this.spawnargs = init.spawnargs;
    this.cmdId = init.cmdId;
    this.started = new Promise<void>((resolve, reject) => {
      this.markStarted = resolve;
      this.failStart = reject;
    });
    // Waited on by input and signals only, which drop what the failure made
    // moot; the failure itself is the `error` event.
    this.started.catch(() => {});

    this.stdin =
      init.stdio[0] === "pipe"
        ? new Writable({
            write: (chunk: Buffer, _encoding, callback) => {
              this.started.then(() => {
                this.channel.input({ stdin: chunk });
                callback();
              }, () => callback());
            },
            final: (callback) => {
              this.started.then(() => {
                this.channel.input({ isStdinEof: true });
                callback();
              }, () => callback());
            },
          })
        : null;
    // The gRPC stream is not paused for a slow reader, so output is buffered
    // here rather than held back in the guest.
    this.stdout = init.stdio[1] === "pipe" ? new Readable({ read() {} }) : null;
    this.stderr = init.stdio[2] === "pipe" ? new Readable({ read() {} }) : null;
    this.stdio = [this.stdin, this.stdout, this.stderr];

    const killSignal = init.killSignal ?? "SIGTERM";
    if (init.timeout && init.timeout > 0) {
      this.timer = setTimeout(() => this.kill(killSignal), init.timeout);
    }
    const signal = init.signal;
    if (signal) {
      const onAbort = () => {
        if (this.kill(killSignal)) this.emit("error", abortError(signal));
      };
      if (signal.aborted) process.nextTick(onAbort);
      else {
        signal.addEventListener("abort", onAbort, { once: true });
        this.unbindAbort = () => signal.removeEventListener("abort", onAbort);
      }
    }

    if (init.cmdId) process.nextTick(() => this.start());
    void this.pump();
  }

  private start(): void {
    if (this.hasStarted) return;
    this.hasStarted = true;
    this.markStarted();
    this.emit("spawn");
  }

  private get exited(): boolean {
    return this.exitCode !== null || this.signalCode !== null;
  }

  private async pump(): Promise<void> {
    let exitSignal = 0;
    try {
      for await (const msg of this.channel.output) {
        switch (msg.output) {
          case "commandId":
            this.cmdId = String(msg.commandId);
            this.start();
            break;
          case "stdout":
          case "stderr": {
            // An older agent sends no id, so its first output is the start.
            this.start();
            const bytes: Uint8Array = msg[msg.output];
            if (bytes.length) (msg.output === "stdout" ? this.stdout : this.stderr)?.push(Buffer.from(bytes));
            break;
          }
          case "exitSignal":
            // Sent just before the exit code, which is then 128 plus it.
            exitSignal = msg.exitSignal;
            break;
          case "lostBytes":
            this.emit("lost", Number(msg.lostBytes));
            break;
          case "exitCode":
            this.start();
            this.exitCode = exitSignal ? null : msg.exitCode;
            this.signalCode = exitSignal ? (SIGNAL_NAMES.get(exitSignal) ?? null) : null;
            this.emit("exit", this.exitCode, this.signalCode);
            break;
        }
      }
      if (!this.exited) {
        throw new BurrowError("the command's output ended before it exited", "unavailable");
      }
    } catch (err) {
      this.failStart(err);
      this.emit("error", err);
    } finally {
      this.finish();
    }
  }

  /** Ends the streams and, once output is drained, says `close`, as Node does. */
  private finish(): void {
    clearTimeout(this.timer);
    this.unbindAbort();
    this.channel.end();
    this.stdin?.destroy();
    const outputs = [this.stdout, this.stderr].filter((s): s is Readable => s !== null);
    for (const stream of outputs) stream.push(null);
    if (!this.exited) return;
    // Output nobody reads is drained, as Node drains it, or `close` would
    // wait on it forever.
    process.nextTick(() => {
      for (const stream of outputs) if (stream.readableFlowing === null) stream.resume();
    });
    Promise.all(
      outputs.map((stream) => new Promise<void>((resolve) => finished(stream, () => resolve()))),
    ).then(() => this.emit("close", this.exitCode, this.signalCode));
  }

  /**
   * Signals the command, SIGTERM unless told otherwise; names are Linux's
   * signals and numbers are sent as they are. Returns false once it has
   * exited, true otherwise: delivery is asynchronous, and a refusal (an exec
   * policy that forbids commands, a suspended sandbox) arrives as `error`.
   * Signal 0 sends nothing and reports whether the command is still running.
   */
  kill(signal: NodeJS.Signals | number = "SIGTERM"): boolean {
    const number = toSignal(signal);
    if (this.exited) return false;
    if (number === 0) return true;
    this.killed = true;
    this.started.then(
      () => this.channel.signal(number, this.cmdId).catch((err) => this.emit("error", err)),
      () => {},
    );
    return true;
  }

  /** Node's no-op for a child that is not keeping the event loop alive. */
  ref(): void {}

  unref(): void {}
}

/** A command started over `Exec`. */
function execChannel(guest: GuestLink, start: object, closeStdin: boolean): Channel {
  let call: any;
  const open = () => {
    // A command outlives any request deadline; `timeout` is its own clock.
    const opened = guest.node().openStream<any>("Exec", start, Infinity);
    call = opened.call;
    // EOF without ending the request side, which signals still use.
    if (closeStdin) call.write({ isStdinEof: true });
    return opened.output;
  };
  const output = (async function* () {
    let stream = open();
    let first: IteratorResult<any>;
    try {
      first = await stream.next();
    } catch (err) {
      // Nothing has reached the command but its start, so a suspended
      // sandbox is resumed and the command started once more.
      if (!guest.autoResume || !(err instanceof BurrowError) || !err.isSuspended) throw err;
      await guest.resume();
      stream = open();
      first = await stream.next();
    }
    if (first.done) return;
    yield first.value;
    yield* stream;
  })();
  return {
    output,
    input: (message) => call.write(message),
    // The id is the address the node signals by; an agent too old to send
    // one is signalled down the stream instead.
    signal: async (signal, cmdId) => {
      if (cmdId) await guest.signalCommand(cmdId, signal);
      else call.write({ signal });
    },
    end: () => call.end(),
  };
}

/** @internal A command reached by id over `Attach`: replayed from `fromOffset`, then followed. */
export function attach(guest: GuestLink, cmdId: string, fromOffset: number, cmd: string[]): ChildProcess {
  const { call, output } = guest.node().openStream<any>(
    "Attach",
    { start: { sandboxId: guest.sandboxId, commandId: cmdId, fromOffset } },
    Infinity,
  );
  return new ChildProcess(
    {
      output,
      input: (message) => call.write(message),
      signal: (signal) => guest.signalCommand(cmdId, signal),
      end: () => call.end(),
    },
    {
      spawnfile: cmd[0] ?? "",
      spawnargs: cmd,
      stdio: ["pipe", "pipe", "pipe"],
      cmdId,
    },
  );
}

function stdioOf(stdio: SpawnOptions["stdio"]): [StdioMode, StdioMode, StdioMode] {
  const modes = typeof stdio === "string" || stdio === undefined ? [stdio, stdio, stdio] : stdio;
  return modes.map((mode) => {
    if (mode === undefined || mode === null) return "pipe";
    if (mode !== "pipe" && mode !== "ignore") throw invalidArgValue("stdio", stdio);
    return mode;
  }) as [StdioMode, StdioMode, StdioMode];
}

/**
 * Starting commands in the sandbox, as `node:child_process`.
 *
 * ```ts
 * const { stdout } = await sandbox.childProcess.exec("ls -la /work");
 * const { stdout: version } = await sandbox.childProcess.execFile("python3", ["--version"]);
 * ```
 *
 * Commands run as the handle's user, with the handle's `env` under their own.
 * Only the asynchronous API: a sync call would block this process on the
 * network. Methods are bound, so `const { exec } = sandbox.childProcess`
 * works as it does with `child_process`.
 */
export class SandboxChildProcess {
  /** @internal */
  constructor(private readonly guest: GuestLink) {
    for (const name of Object.getOwnPropertyNames(SandboxChildProcess.prototype)) {
      const value = (this as any)[name];
      if (name !== "constructor" && typeof value === "function") (this as any)[name] = value.bind(this);
    }
  }

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
    let file = command;
    let argv = args;
    if (options.shell) {
      // Node's own construction: the words joined with spaces, unquoted.
      file = typeof options.shell === "string" ? options.shell : "/bin/sh";
      argv = ["-c", [command, ...args].join(" ")];
    }
    const stdio = stdioOf(options.stdio);
    const env: Record<string, string> = { ...this.guest.env };
    for (const [name, value] of Object.entries(options.env ?? {})) {
      if (value !== undefined) env[name] = value;
    }
    const start = {
      start: {
        sandboxId: this.guest.sandboxId,
        cmd: [file, ...argv],
        env,
        cwd: options.cwd === undefined ? "" : toPath(options.cwd),
        isPty: options.pty ?? false,
        rows: options.rows ?? 24,
        cols: options.cols ?? 80,
        user: options.user ?? this.guest.user,
        logMaxBytes: options.logMaxBytes ?? 0,
        logMaxFiles: options.logMaxFiles ?? 0,
      },
    };
    return new ChildProcess(execChannel(this.guest, start, stdio[0] === "ignore"), {
      spawnfile: file,
      spawnargs: [file, ...argv],
      stdio,
      timeout: options.timeout,
      killSignal: options.killSignal,
      signal: options.signal,
    });
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
}

/** Gathers a child's output and settles as Node's `exec` callback does. */
function collect(
  child: ChildProcess,
  cmd: string,
  options: ExecFileOptions,
): PromiseWithChild<{ stdout: string | Buffer; stderr: string | Buffer }> {
  const maxBuffer = options.maxBuffer ?? 1024 * 1024;
  const encoding =
    options.encoding !== "buffer" && options.encoding !== null ? (options.encoding ?? "utf8") : null;
  const output = { stdout: [] as Buffer[], stderr: [] as Buffer[] };
  let failure: Error | undefined;

  const promise = new Promise<{ stdout: string | Buffer; stderr: string | Buffer }>((resolve, reject) => {
    for (const name of ["stdout", "stderr"] as const) {
      let size = 0;
      child[name]!.on("data", (chunk: Buffer) => {
        const room = maxBuffer - size;
        size += chunk.length;
        if (size <= maxBuffer) {
          output[name].push(chunk);
          return;
        }
        // As much as fits is kept, and the command is stopped, as Node does.
        if (room > 0) output[name].push(chunk.subarray(0, room));
        if (!failure) {
          failure = Object.assign(new RangeError(`${name} maxBuffer length exceeded`), {
            code: "ERR_CHILD_PROCESS_STDIO_MAXBUFFER",
          });
          child.kill(options.killSignal ?? "SIGTERM");
        }
      });
    }

    let settled = false;
    const settle = (code: number | null, signal: NodeJS.Signals | null) => {
      if (settled) return;
      settled = true;
      const bytes = { stdout: Buffer.concat(output.stdout), stderr: Buffer.concat(output.stderr) };
      const stdout = encoding ? bytes.stdout.toString(encoding) : bytes.stdout;
      const stderr = encoding ? bytes.stderr.toString(encoding) : bytes.stderr;
      if (!failure && code === 0 && signal === null) {
        resolve({ stdout, stderr });
        return;
      }
      const err =
        failure ??
        Object.assign(new Error(`Command failed: ${cmd}\n${stderr}`), {
          code,
          killed: child.killed,
          signal,
        });
      reject(Object.assign(err, { cmd, stdout, stderr }));
    };
    child.on("close", settle);
    child.on("error", (err: Error) => {
      failure ??= err;
      settle(child.exitCode, child.signalCode);
    });
  });
  return Object.assign(promise, { child });
}
