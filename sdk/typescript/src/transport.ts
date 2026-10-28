/**
 * gRPC transport. Internal: the public surface in `sandbox.ts` is hand-written
 * and does not mirror the RPC shapes.
 *
 * Protos are loaded at runtime with `@grpc/proto-loader` rather than compiled
 * ahead of time, so the package needs no code generation step and ships the
 * same `.proto` files the daemons are built from.
 */

import { EventEmitter } from "node:events";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";

import { BurrowError } from "./errors.js";

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));

/** Resolves `proto/` whether running from `src/` or from built `dist/`. */
function protoDir(): string {
  for (const candidate of [
    resolve(here, "../proto"),
    resolve(here, "../../proto"),
  ]) {
    try {
      require.resolve(resolve(candidate, "api.proto"));
      return candidate;
    } catch {
      // Not this one; try the next.
    }
  }
  // require.resolve rejects non-JS files in some setups, so fall back to the
  // layout of a published package.
  return resolve(here, "../proto");
}

export interface TransportOptions {
  /** Orchestrator address, e.g. `localhost:7070` or `http://localhost:7070`. */
  endpoint?: string;
  /** Bearer token, sent as `authorization: Bearer <token>` on every call. */
  apiKey?: string;
  /** Use TLS. Defaults to true for `https://` endpoints, false otherwise. */
  tls?: boolean;
  /** Default per-call deadline in milliseconds. */
  timeoutMs?: number;
  /**
   * Where exec, attach and file traffic goes. `"direct"`, the default, calls
   * the node holding the sandbox with a short-lived token from the
   * orchestrator, and needs the node reachable from here. `"orchestrator"`
   * has the orchestrator relay the calls. Neither falls back to the other.
   * Reads `BURROW_ROUTE`.
   */
  route?: "direct" | "orchestrator";
}

type AnyClient = grpc.Client & Record<string, Function>;

/** Whether `host` is plainly this machine, not some other one on the network. */
function isLoopbackHost(host: string): boolean {
  const bare = host.replace(/^\[/, "").replace(/\]$/, "");
  return (
    bare === "localhost" ||
    bare === "::1" ||
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(bare)
  );
}

/**
 * Cancels `call` when `signal` aborts, and returns a cleanup function.
 *
 * grpc-js has no `AbortSignal`, but a cancelled call surfaces as `CANCELLED`,
 * which is what an aborted request should look like.
 */
function bindSignal(call: any, signal: AbortSignal | undefined): () => void {
  if (!signal) return () => {};
  if (signal.aborted) {
    call.cancel();
    return () => {};
  }
  const onAbort = () => call.cancel();
  signal.addEventListener("abort", onAbort, { once: true });
  return () => signal.removeEventListener("abort", onAbort);
}

/** A token is replaced this long before it expires. */
const GRANT_MARGIN_MS = 30_000;

/**
 * What a node says about a token that no longer works there: expired,
 * revoked, or for a sandbox that has moved to another node.
 */
const STALE_GRANT = new Set(["unauthenticated", "not_found"]);

const CHANNEL_OPTIONS = {
  // Exec and file transfers can carry large payloads; the 4MB default turns a
  // big file into a confusing RESOURCE_EXHAUSTED.
  "grpc.max_receive_message_length": 64 * 1024 * 1024,
  "grpc.max_send_message_length": 64 * 1024 * 1024,
};

export class Transport {
  private readonly client: AnyClient;
  private readonly pkg: any;
  private readonly directs = new Map<string, Direct>();
  private readonly nodes = new Map<string, AnyClient>();
  readonly timeoutMs: number;
  /**
   * Host this client dials, without its port. A published port whose node
   * advertises no address of its own is reachable here, the single-node case.
   */
  readonly host: string;
  private readonly apiKey?: string;
  private readonly isRelayed: boolean;
  /** Handles sharing this connection; the channel outlives the first release. */
  private refs = 1;

  constructor(options: TransportOptions = {}) {
    const raw =
      options.endpoint ?? process.env.BURROW_ENDPOINT ?? "localhost:7070";
    const secure = options.tls ?? raw.startsWith("https://");
    const address = raw.replace(/^https?:\/\//, "");

    this.host = address.replace(/:\d+$/, "") || "localhost";
    this.timeoutMs = options.timeoutMs ?? 60_000;
    this.apiKey = options.apiKey ?? process.env.BURROW_API_KEY;
    const route = options.route ?? process.env.BURROW_ROUTE ?? "direct";
    if (route !== "direct" && route !== "orchestrator") {
      throw new BurrowError(
        `route must be "direct" or "orchestrator", not ${JSON.stringify(route)}`,
        "invalid_argument",
      );
    }
    this.isRelayed = route === "orchestrator";

    // A bare `host:port` endpoint leaves `tls` false, which is fine with no
    // credential in play but an easy way to ship an API key in cleartext to
    // whatever `BURROW_ENDPOINT` is set to in production. Refused rather
    // than warned, unless the destination is obviously the caller's own
    // machine or `tls`/the endpoint scheme said so explicitly.
    if (
      this.apiKey &&
      !secure &&
      options.tls === undefined &&
      !raw.startsWith("http://") &&
      !isLoopbackHost(this.host)
    ) {
      throw new BurrowError(
        `refusing to send an API key over a plaintext connection to ${this.host}; ` +
          `pass tls explicitly if that's intended`,
        "invalid_argument",
      );
    }

    const definition = protoLoader.loadSync("api.proto", {
      includeDirs: [protoDir()],
      keepCase: false,
      longs: Number,
      enums: String,
      defaults: true,
      oneofs: true,
    });
    this.pkg = grpc.loadPackageDefinition(definition) as any;
    const Ctor = this.pkg.burrow.api.v1.Burrow;

    this.client = new Ctor(
      address,
      secure
        ? grpc.credentials.createSsl()
        : grpc.credentials.createInsecure(),
      CHANNEL_OPTIONS,
    ) as AnyClient;
  }

  /**
   * Where a sandbox's exec, attach and file calls go: its node, or this
   * connection to the orchestrator, which relays them. Both take the same
   * calls.
   */
  route(sandboxId: string): Transport | Direct {
    return this.isRelayed ? this : this.direct(sandboxId);
  }

  /** The way to a sandbox's exec, attach and file calls: its node. */
  direct(sandboxId: string): Direct {
    let direct = this.directs.get(sandboxId);
    if (!direct) {
      direct = new Direct(this, sandboxId);
      this.directs.set(sandboxId, direct);
    }
    return direct;
  }

  /** @internal One client per node, shared by every sandbox on it. */
  nodeClient(endpoint: string): AnyClient {
    let client = this.nodes.get(endpoint);
    if (!client) {
      const address = endpoint.replace(/^https?:\/\//, "");
      let credentials: grpc.ChannelCredentials;
      if (endpoint.startsWith("https://")) credentials = grpc.credentials.createSsl();
      // The node's operator advertised it as plain http, which is as explicit
      // as a caller passing `http://` here.
      else if (endpoint.startsWith("http://")) credentials = grpc.credentials.createInsecure();
      else throw new BurrowError(`node endpoint ${endpoint} names no scheme`, "internal");
      const Ctor = this.pkg.burrow.api.v1.Access;
      client = new Ctor(address, credentials, CHANNEL_OPTIONS) as AnyClient;
      this.nodes.set(endpoint, client);
    }
    return client;
  }

  private metadata(): grpc.Metadata {
    const md = new grpc.Metadata();
    if (this.apiKey) md.set("authorization", `Bearer ${this.apiKey}`);
    return md;
  }

  /**
   * Per-call deadline. `Infinity` means none, which is what long-lived streams
   * like watches need: grpc-js rejects a far-future deadline rather than
   * reading it as "never".
   */
  private deadline(timeoutMs?: number): grpc.CallOptions {
    const timeout = timeoutMs ?? this.timeoutMs;
    if (!Number.isFinite(timeout)) return {};
    return { deadline: Date.now() + timeout };
  }

  /** Unary call. */
  unary<Req, Res>(
    method: string,
    request: Req,
    timeoutMs?: number,
    signal?: AbortSignal,
  ): Promise<Res> {
    return new Promise((resolvePromise, reject) => {
      let release = () => {};
      const call = this.client[method]!(
        request,
        this.metadata(),
        this.deadline(timeoutMs),
        (err: grpc.ServiceError | null, res: Res) => {
          release();
          if (err) reject(BurrowError.fromGrpc(err));
          else resolvePromise(res);
        },
      );
      release = bindSignal(call, signal);
    });
  }

  /** Server-streaming call, surfaced as an async iterable. */
  async *serverStream<Req, Res>(
    method: string,
    request: Req,
    timeoutMs?: number,
    signal?: AbortSignal,
  ): AsyncGenerator<Res> {
    const call = this.client[method]!(
      request,
      this.metadata(),
      this.deadline(timeoutMs),
    );
    const release = bindSignal(call, signal);
    try {
      yield* iterate<Res>(call);
    } finally {
      release();
    }
  }

  /**
   * Bidirectional call where the client sends `requests` and then closes.
   *
   * Burrow's streaming RPCs all begin with one message that names the sandbox,
   * so this covers exec and upload without exposing a duplex stream.
   */
  async *pipe<Req, Res>(
    method: string,
    requests: Req[],
    timeoutMs?: number,
    signal?: AbortSignal,
  ): AsyncGenerator<Res> {
    const call = this.client[method]!(this.metadata(), this.deadline(timeoutMs));
    const release = bindSignal(call, signal);
    for (const request of requests) call.write(request);
    call.end();
    try {
      yield* iterate<Res>(call);
    } finally {
      release();
    }
  }

  /**
   * Raw bidirectional call, for streams whose input stays open. {@link pipe}
   * closes the request side at once, which an interactive terminal cannot use.
   */
  duplex(method: string, timeoutMs = Infinity, signal?: AbortSignal): any {
    const call = this.client[method]!(this.metadata(), this.deadline(timeoutMs));
    bindSignal(call, signal);
    return call;
  }

  /**
   * Bidirectional call, opened with `first` and left writable: a detached
   * command reads its output as a stream while still able to send a signal.
   */
  openStream<Res>(
    method: string,
    first: unknown,
    timeoutMs?: number,
    signal?: AbortSignal,
  ): { call: any; output: AsyncGenerator<Res> } {
    const call = this.client[method]!(this.metadata(), this.deadline(timeoutMs));
    const release = bindSignal(call, signal);
    call.write(first);
    // Eager, so output produced before the caller reads is buffered.
    const messages = iterate<Res>(call);
    const output = (async function* () {
      try {
        yield* messages;
      } finally {
        release();
      }
    })();
    return { call, output };
  }

  /** Bidi call whose single response is awaited (upload). */
  pipeUnary<Req, Res>(
    method: string,
    requests: Req[],
    timeoutMs?: number,
    signal?: AbortSignal,
  ): Promise<Res> {
    return new Promise((resolvePromise, reject) => {
      let release = () => {};
      const call = this.client[method]!(
        this.metadata(),
        this.deadline(timeoutMs),
        (err: grpc.ServiceError | null, res: Res) => {
          release();
          if (err) reject(BurrowError.fromGrpc(err));
          else resolvePromise(res);
        },
      );
      release = bindSignal(call, signal);
      for (const request of requests) call.write(request);
      call.end();
    });
  }

  /** Claims a share of this connection. Undone by one {@link close}. */
  retain(): this {
    this.refs++;
    return this;
  }

  /** Releases one share; the channel closes when the last one goes. */
  close(): void {
    if (--this.refs <= 0) {
      this.client.close();
      for (const node of this.nodes.values()) node.close();
    }
  }
}

interface Grant {
  endpoint: string;
  token: string;
  /** Unix seconds. */
  expiresAt: number;
  sandboxId: string;
}

/**
 * A sandbox's exec, attach and file calls, made on the node that holds it.
 *
 * The orchestrator carries none of that traffic: it issues a short-lived token
 * for the sandbox's node, and the node is called with it. The token is reused
 * until it nears expiry, and replaced when the node refuses it, as it does once
 * it has expired, been revoked, or the sandbox has moved. A call that sends one
 * message is then made once more; a stream is not, since what it already sent
 * cannot be taken back, and the next one gets a fresh token.
 */
export class Direct {
  private grant?: Promise<Grant>;

  /** @internal */
  constructor(
    private readonly transport: Transport,
    readonly sandboxId: string,
  ) {}

  private current(renew = false): Promise<Grant> {
    const held = this.grant;
    if (!renew && held) {
      return held.then((grant) =>
        grant.expiresAt * 1000 - Date.now() < GRANT_MARGIN_MS ? this.current(true) : grant,
      );
    }
    const issued = this.transport
      .unary<any, Grant>("IssueAccess", { ref: { id: this.sandboxId } })
      .catch((err) => {
        // A failed issue is not kept, so the next call asks again.
        if (this.grant === issued) this.grant = undefined;
        throw err;
      });
    this.grant = issued;
    return issued;
  }

  private target(grant: Grant): { client: AnyClient; metadata: grpc.Metadata } {
    const metadata = new grpc.Metadata();
    metadata.set("authorization", `Bearer ${grant.token}`);
    return { client: this.transport.nodeClient(grant.endpoint), metadata };
  }

  private deadline(timeoutMs?: number): grpc.CallOptions {
    const timeout = timeoutMs ?? this.transport.timeoutMs;
    if (!Number.isFinite(timeout)) return {};
    return { deadline: Date.now() + timeout };
  }

  private async onceMore<T>(call: (grant: Grant) => Promise<T>): Promise<T> {
    try {
      return await call(await this.current());
    } catch (err) {
      if (!(err instanceof BurrowError) || !STALE_GRANT.has(err.code)) throw err;
    }
    return call(await this.current(true));
  }

  /** Unary call. */
  unary<Req, Res>(
    method: string,
    request: Req,
    timeoutMs?: number,
    signal?: AbortSignal,
  ): Promise<Res> {
    return this.onceMore(
      (grant) =>
        new Promise<Res>((resolvePromise, reject) => {
          const { client, metadata } = this.target(grant);
          let release = () => {};
          const call = client[method]!(
            request,
            metadata,
            this.deadline(timeoutMs),
            (err: grpc.ServiceError | null, res: Res) => {
              release();
              if (err) reject(BurrowError.fromGrpc(err));
              else resolvePromise(res);
            },
          );
          release = bindSignal(call, signal);
        }),
    );
  }

  /** Server-streaming call, surfaced as an async iterable. */
  async *serverStream<Req, Res>(
    method: string,
    request: Req,
    timeoutMs?: number,
    signal?: AbortSignal,
  ): AsyncGenerator<Res> {
    const { client, metadata } = this.target(await this.current());
    const call = client[method]!(request, metadata, this.deadline(timeoutMs));
    const release = bindSignal(call, signal);
    try {
      yield* iterate<Res>(call);
    } finally {
      release();
    }
  }

  /** Bidi call whose single response is awaited (upload). */
  pipeUnary<Req, Res>(
    method: string,
    requests: Req[],
    timeoutMs?: number,
    signal?: AbortSignal,
  ): Promise<Res> {
    return this.onceMore(
      (grant) =>
        new Promise<Res>((resolvePromise, reject) => {
          const { client, metadata } = this.target(grant);
          let release = () => {};
          const call = client[method]!(
            metadata,
            this.deadline(timeoutMs),
            (err: grpc.ServiceError | null, res: Res) => {
              release();
              if (err) reject(BurrowError.fromGrpc(err));
              else resolvePromise(res);
            },
          );
          release = bindSignal(call, signal);
          for (const request of requests) call.write(request);
          call.end();
        }),
    );
  }

  /**
   * Bidirectional call, returned at once and opened once the token is in
   * hand: writes, `end` and `cancel` made before then are applied in order
   * when it opens, and its events are passed on.
   */
  duplex(method: string, timeoutMs = Infinity, signal?: AbortSignal): any {
    const call = new LazyCall();
    this.current().then(
      (grant) => {
        const { client, metadata } = this.target(grant);
        const opened = client[method]!(metadata, this.deadline(timeoutMs));
        bindSignal(opened, signal);
        call.open(opened);
      },
      (err) => call.fail(err),
    );
    return call;
  }

  /**
   * Bidirectional call, opened with `first` and left writable: a command's
   * output is read as a stream while it can still be fed and signalled.
   */
  openStream<Res>(
    method: string,
    first: unknown,
    timeoutMs?: number,
    signal?: AbortSignal,
  ): { call: any; output: AsyncGenerator<Res> } {
    const call = this.duplex(method, timeoutMs ?? this.transport.timeoutMs, signal);
    call.write(first);
    // Eager, so output produced before the caller reads is buffered.
    return { call, output: iterate<Res>(call) };
  }
}

/** A call that exists before the one it stands in for has been opened. */
class LazyCall extends EventEmitter {
  private real?: any;
  private pending: Array<(call: any) => void> = [];
  private cancelled = false;

  /** @internal */
  open(call: any): void {
    if (this.cancelled) {
      call.cancel();
      return;
    }
    this.real = call;
    for (const event of ["data", "error", "end", "status"]) {
      call.on(event, (value: unknown) => this.emit(event, value));
    }
    for (const apply of this.pending) apply(call);
    this.pending = [];
  }

  /** @internal The token could not be had, so the call never opens. */
  fail(err: unknown): void {
    if (this.cancelled) return;
    this.emit(
      "error",
      err instanceof BurrowError ? err : new BurrowError(String(err), "unavailable"),
    );
  }

  private apply(action: (call: any) => void): void {
    if (this.real) action(this.real);
    else this.pending.push(action);
  }

  write(message: unknown): boolean {
    this.apply((call) => call.write(message));
    return true;
  }

  end(): void {
    this.apply((call) => call.end());
  }

  cancel(): void {
    if (this.real) this.real.cancel();
    else this.cancelled = true;
  }
}

/**
 * Adapts a gRPC call to an async iterable. Errors arrive on an `error` event
 * rather than rejecting iteration, so they are re-raised into the iterator to
 * keep `for await` and `try/catch` behaving as callers expect.
 */
function iterate<T>(call: any): AsyncGenerator<T> {
  const queue: T[] = [];
  let failure: Error | undefined;
  let done = false;
  let wake: (() => void) | undefined;

  const notify = () => {
    wake?.();
    wake = undefined;
  };

  call.on("data", (msg: T) => {
    queue.push(msg);
    notify();
  });
  call.on("error", (err: grpc.ServiceError | BurrowError) => {
    // CANCELLED after a clean end is how grpc-js reports a stream the caller
    // stopped reading; it is not a failure worth surfacing.
    if (err instanceof BurrowError) {
      failure = err;
    } else if (!done || err.code !== grpc.status.CANCELLED) {
      failure = BurrowError.fromGrpc(err);
    }
    done = true;
    notify();
  });
  call.on("end", () => {
    done = true;
    notify();
  });

  // Listeners are attached above rather than on first `next()`: an `error`
  // with nobody listening takes the process down.
  return (async function* () {
    try {
      while (true) {
        while (queue.length > 0) yield queue.shift()!;
        if (failure) throw failure;
        if (done) return;
        await new Promise<void>((r) => {
          wake = r;
        });
      }
    } finally {
      // Abandoning the loop early (break, throw) must not leak the call.
      if (!done) call.cancel();
    }
  })();
}
