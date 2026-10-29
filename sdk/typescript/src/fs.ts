/**
 * `sandbox.fs`: Node's `fs/promises`, performed by the guest kernel.
 *
 * Every call is one `Fs` RPC carrying one POSIX operation, so the semantics
 * are the kernel's own: what `open(2)` would refuse is refused, with the errno
 * it would have set. Signatures, defaults and errors follow `fs/promises`, so
 * code written against it runs here with `fs` swapped for `sandbox.fs`.
 */

import { Buffer } from "node:buffer";
import type { Abortable } from "node:events";
import type {
  BufferEncodingOption,
  CopyOptions,
  Dirent as NodeDirent,
  EncodingOption,
  MakeDirectoryOptions,
  Mode,
  ObjectEncodingOptions,
  OpenMode,
  PathLike,
  ReadOptions,
  ReadOptionsWithBuffer,
  ReadPosition,
  ReadVResult,
  RmDirOptions,
  RmOptions,
  Stats as NodeStats,
  StatOptions,
  TimeLike,
  WatchOptions as NodeWatchOptions,
  WriteVResult,
} from "node:fs";
import type {
  CreateReadStreamOptions,
  CreateWriteStreamOptions,
  FileChangeInfo,
  FileReadResult,
} from "node:fs/promises";
import { posix } from "node:path";
import { createInterface, type Interface } from "node:readline";
import { Readable, Writable } from "node:stream";
import { getSystemErrorMap, inspect } from "node:util";

import { BurrowError } from "./errors.js";
import type { GuestLink } from "./guest.js";

/**
 * Linux's values, not this machine's: the guest is always Linux, and a flag
 * or mode bit is interpreted there. On macOS `O_CREAT` alone differs.
 */
export const constants = Object.freeze({
  F_OK: 0,
  X_OK: 1,
  W_OK: 2,
  R_OK: 4,
  O_RDONLY: 0,
  O_WRONLY: 1,
  O_RDWR: 2,
  O_CREAT: 0o100,
  O_EXCL: 0o200,
  O_TRUNC: 0o1000,
  O_APPEND: 0o2000,
  COPYFILE_EXCL: 1,
  COPYFILE_FICLONE: 2,
  COPYFILE_FICLONE_FORCE: 4,
  S_IFMT: 0o170000,
  S_IFREG: 0o100000,
  S_IFDIR: 0o40000,
  S_IFCHR: 0o20000,
  S_IFBLK: 0o60000,
  S_IFIFO: 0o10000,
  S_IFLNK: 0o120000,
  S_IFSOCK: 0o140000,
  S_IRWXU: 0o700,
  S_IRUSR: 0o400,
  S_IWUSR: 0o200,
  S_IXUSR: 0o100,
  S_IRWXG: 0o70,
  S_IRGRP: 0o40,
  S_IWGRP: 0o20,
  S_IXGRP: 0o10,
  S_IRWXO: 0o7,
  S_IROTH: 0o4,
  S_IWOTH: 0o2,
  S_IXOTH: 0o1,
});

const { O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_EXCL, O_TRUNC, O_APPEND } = constants;

/**
 * Node's string flags. The `s` (synchronous) variants are absent: the agent
 * opens with no `O_SYNC`, and quietly dropping it would claim a durability
 * the write does not have.
 */
const FLAGS: Record<string, number> = {
  r: O_RDONLY,
  "r+": O_RDWR,
  w: O_TRUNC | O_CREAT | O_WRONLY,
  "w+": O_TRUNC | O_CREAT | O_RDWR,
  wx: O_TRUNC | O_CREAT | O_WRONLY | O_EXCL,
  xw: O_TRUNC | O_CREAT | O_WRONLY | O_EXCL,
  "wx+": O_TRUNC | O_CREAT | O_RDWR | O_EXCL,
  "xw+": O_TRUNC | O_CREAT | O_RDWR | O_EXCL,
  a: O_APPEND | O_CREAT | O_WRONLY,
  "a+": O_APPEND | O_CREAT | O_RDWR,
  ax: O_APPEND | O_CREAT | O_WRONLY | O_EXCL,
  xa: O_APPEND | O_CREAT | O_WRONLY | O_EXCL,
  "ax+": O_APPEND | O_CREAT | O_RDWR | O_EXCL,
  "xa+": O_APPEND | O_CREAT | O_RDWR | O_EXCL,
};

/** The agent's ceiling on one read or write. */
const MAX_IO = 4 * 1024 * 1024;

/** What `filehandle.read()` allocates when given no buffer, as Node does. */
const DEFAULT_READ = 16 * 1024;

/**
 * Descriptions by errno name. libuv's strings, which are what Node prints,
 * and the same on every platform even where the numbers are not.
 */
const DESCRIPTIONS = new Map(
  [...getSystemErrorMap().values()].map(([name, description]) => [name, description]),
);

/** Node's system error, which names a second path where the call had one. */
type SystemError = NodeJS.ErrnoException & { dest?: string };

/** A guest kernel error, shaped exactly as Node's own `fs` reports one. */
function fsError(raw: any): SystemError {
  let message = `${raw.code}: ${DESCRIPTIONS.get(raw.code) ?? "unknown error"}, ${raw.syscall}`;
  if (raw.path) message += ` '${raw.path}'`;
  if (raw.dest) message += ` -> '${raw.dest}'`;
  const err: SystemError = new Error(message);
  // Negative, as libuv reports it. The guest's number, which is Linux's.
  err.errno = -raw.errno;
  err.code = raw.code;
  err.syscall = raw.syscall;
  if (raw.path) err.path = raw.path;
  if (raw.dest) err.dest = raw.dest;
  return err;
}

/** Node's `AbortError`, which an aborted `fs` call rejects with. */
export function abortError(signal: AbortSignal): Error {
  return Object.assign(new Error("The operation was aborted", { cause: signal.reason }), {
    name: "AbortError",
    code: "ABORT_ERR",
  });
}

export function invalidArgValue(name: string, value: unknown): TypeError {
  return Object.assign(
    new TypeError(`The argument '${name}' is invalid. Received ${inspect(value)}`),
    { code: "ERR_INVALID_ARG_VALUE" },
  );
}

function toFlags(flags: OpenMode | null | undefined, fallback: string): number {
  if (flags === undefined || flags === null) return FLAGS[fallback]!;
  if (typeof flags === "number") return flags;
  const value = FLAGS[flags];
  if (value === undefined) throw invalidArgValue("flags", flags);
  return value;
}

function toMode(mode: Mode | null | undefined, fallback: number): number {
  if (mode === undefined || mode === null) return fallback;
  return typeof mode === "string" ? parseInt(mode, 8) : mode;
}

/** A guest path. A `file:` URL is its pathname, as Node reads one. */
export function toPath(path: PathLike): string {
  if (typeof path === "string") return path;
  if (path instanceof URL) {
    if (path.protocol !== "file:") {
      throw Object.assign(new TypeError("The URL must be of scheme file"), {
        code: "ERR_INVALID_URL_SCHEME",
      });
    }
    return decodeURIComponent(path.pathname);
  }
  return path.toString();
}

/**
 * Nanoseconds since the epoch, as a decimal string: a number cannot hold them
 * exactly, and the wire field is 64-bit. Node's coercion: a number or numeric
 * string is seconds, and a time that is not finite means now.
 */
function toNanos(time: TimeLike): string {
  let seconds: number;
  if (time instanceof Date) seconds = time.getTime() / 1000;
  else if (typeof time === "number") seconds = time;
  else if (typeof time === "string" && time.trim() !== "" && Number.isFinite(Number(time))) {
    seconds = Number(time);
  } else {
    throw Object.assign(
      new TypeError(
        `The "time" argument must be of type number, string or Date. Received ${inspect(time)}`,
      ),
      { code: "ERR_INVALID_ARG_TYPE" },
    );
  }
  if (!Number.isFinite(seconds) || seconds < 0) seconds = Date.now() / 1000;
  const whole = Math.trunc(seconds);
  return (
    BigInt(whole) * 1_000_000_000n +
    BigInt(Math.round((seconds - whole) * 1e9))
  ).toString();
}

type Encoding = BufferEncoding | "buffer" | null | undefined;

/** Options as Node takes them: an encoding name stands for `{ encoding }`. */
function optionsOf<T extends object>(
  options: T | BufferEncoding | "buffer" | null | undefined,
): Partial<T> & { encoding?: Encoding } {
  return typeof options === "string"
    ? ({ encoding: options } as Partial<T> & { encoding: Encoding })
    : (options ?? {});
}

/** A name or path in the encoding asked for. The wire carries UTF-8. */
function encoded(value: string, encoding: Encoding): string | Buffer {
  if (encoding === "buffer") return Buffer.from(value);
  if (!encoding || encoding === "utf8" || encoding === "utf-8") return value;
  return Buffer.from(value).toString(encoding);
}

function bytesOf(data: string | NodeJS.ArrayBufferView, encoding: Encoding): Buffer {
  if (typeof data === "string") {
    return Buffer.from(data, encoding && encoding !== "buffer" ? encoding : "utf8");
  }
  return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
}

/**
 * Milliseconds, to the microsecond. Nanoseconds since the epoch arrive as a
 * double, good to a few hundred of them, so finer digits would be noise.
 */
function toMs(nanos: number): number {
  return Math.round(nanos / 1e3) / 1e3;
}

/** What one `stat(2)` reports, field for field, as Node's `fs.Stats`. */
export class Stats implements NodeStats {
  dev: number;
  ino: number;
  mode: number;
  nlink: number;
  uid: number;
  gid: number;
  rdev: number;
  size: number;
  blksize: number;
  blocks: number;
  atimeMs: number;
  mtimeMs: number;
  ctimeMs: number;
  /** 0 where the guest filesystem does not record a birth time. */
  birthtimeMs: number;
  atime: Date;
  mtime: Date;
  ctime: Date;
  birthtime: Date;

  /** @internal */
  constructor(raw: any) {
    this.dev = raw.dev;
    this.ino = raw.ino;
    this.mode = raw.mode;
    this.nlink = raw.nlink;
    this.uid = raw.uid;
    this.gid = raw.gid;
    this.rdev = raw.rdev;
    this.size = raw.size;
    this.blksize = raw.blksize;
    this.blocks = raw.blocks;
    this.atimeMs = toMs(raw.atimeNs);
    this.mtimeMs = toMs(raw.mtimeNs);
    this.ctimeMs = toMs(raw.ctimeNs);
    this.birthtimeMs = toMs(raw.birthtimeNs);
    this.atime = new Date(this.atimeMs);
    this.mtime = new Date(this.mtimeMs);
    this.ctime = new Date(this.ctimeMs);
    this.birthtime = new Date(this.birthtimeMs);
  }

  private is(type: number): boolean {
    return (this.mode & constants.S_IFMT) === type;
  }

  isFile(): boolean {
    return this.is(constants.S_IFREG);
  }

  isDirectory(): boolean {
    return this.is(constants.S_IFDIR);
  }

  isSymbolicLink(): boolean {
    return this.is(constants.S_IFLNK);
  }

  isFIFO(): boolean {
    return this.is(constants.S_IFIFO);
  }

  isSocket(): boolean {
    return this.is(constants.S_IFSOCK);
  }

  isCharacterDevice(): boolean {
    return this.is(constants.S_IFCHR);
  }

  isBlockDevice(): boolean {
    return this.is(constants.S_IFBLK);
  }
}

/** A directory entry with its type, as `readdir(..., { withFileTypes: true })` returns. */
export class Dirent<Name extends string | Buffer = string> implements NodeDirent<Name> {
  name: Name;
  parentPath: string;
  /** @deprecated Node's alias for {@link parentPath}. */
  path: string;
  private readonly type: string;

  /** @internal `type` is the agent's d_type name: "file", "dir", "symlink", ... */
  constructor(name: Name, parentPath: string, type: string) {
    this.name = name;
    this.parentPath = parentPath;
    this.path = parentPath;
    this.type = type;
  }

  isFile(): boolean {
    return this.type === "file";
  }

  isDirectory(): boolean {
    return this.type === "dir";
  }

  isSymbolicLink(): boolean {
    return this.type === "symlink";
  }

  isFIFO(): boolean {
    return this.type === "fifo";
  }

  isSocket(): boolean {
    return this.type === "socket";
  }

  isCharacterDevice(): boolean {
    return this.type === "char";
  }

  isBlockDevice(): boolean {
    return this.type === "block";
  }
}

/** The d_type name a `Stats` corresponds to, for entries d_type left unknown. */
function typeOf(stats: Stats): string {
  if (stats.isFile()) return "file";
  if (stats.isDirectory()) return "dir";
  if (stats.isSymbolicLink()) return "symlink";
  if (stats.isFIFO()) return "fifo";
  if (stats.isSocket()) return "socket";
  if (stats.isCharacterDevice()) return "char";
  if (stats.isBlockDevice()) return "block";
  return "unknown";
}

type WriteData =
  | string
  | NodeJS.ArrayBufferView
  | Iterable<string | NodeJS.ArrayBufferView>
  | AsyncIterable<string | NodeJS.ArrayBufferView>;

type ReadFileOptions = ObjectEncodingOptions & Abortable & { flag?: OpenMode };

type WriteFileOptions = ObjectEncodingOptions &
  Abortable & { mode?: Mode; flag?: OpenMode; flush?: boolean };

/** {@link SandboxFs.watch}'s options: Node's, plus the guest's poll interval. */
export interface WatchOptions extends NodeWatchOptions {
  /**
   * Burrow only. How often the guest re-scans, in milliseconds; 500 when
   * omitted. The guest polls rather than using inotify, so a file created and
   * removed between two scans is never reported.
   */
  intervalMs?: number;
}

/**
 * An open file in the sandbox, as `fs/promises`' `FileHandle`.
 *
 * The agent closes a handle left unused for ten minutes, so one held across a
 * long idle stretch reads as `EBADF` afterwards.
 */
export class FileHandle {
  private handle: number;

  /** @internal */
  constructor(
    private readonly fs: SandboxFs,
    handle: number,
    /** The path it was opened by, for the calls the agent has no handle form of. */
    private readonly path: string,
  ) {
    this.handle = handle;
  }

  /** The agent's handle number; -1 once closed, as Node's is. */
  get fd(): number {
    return this.handle;
  }

  /** The handle, or Node's own rejection for a handle already closed. */
  private live(syscall: string): number {
    if (this.handle === -1) {
      const err: NodeJS.ErrnoException = new Error("file closed");
      err.code = "EBADF";
      err.syscall = syscall;
      throw err;
    }
    return this.handle;
  }

  /** Alias of {@link writeFile}, as Node has it: the handle's flags decide where. */
  async appendFile(
    data: WriteData,
    options?: (ObjectEncodingOptions & Abortable) | BufferEncoding | null,
  ): Promise<void> {
    await this.writeFile(data, options);
  }

  /** Path-based: the agent has no `fchmod`, so a file renamed since open is found by its old name. */
  async chmod(mode: Mode): Promise<void> {
    this.live("fchmod");
    await this.fs.chmod(this.path, mode);
  }

  /** Path-based, as {@link chmod} is. */
  async chown(uid: number, gid: number): Promise<void> {
    this.live("fchown");
    await this.fs.chown(this.path, uid, gid);
  }

  async close(): Promise<void> {
    const handle = this.handle;
    if (handle === -1) return;
    this.handle = -1;
    await this.fs.request("close", { handle });
  }

  async datasync(): Promise<void> {
    await this.fs.request("fsync", { handle: this.live("fdatasync"), isDataOnly: true });
  }

  async sync(): Promise<void> {
    await this.fs.request("fsync", { handle: this.live("fsync"), isDataOnly: false });
  }

  /**
   * Reads into `buffer` at `offset`. A `position` of `null` or -1 reads from
   * the handle's own position and moves it; a number is a pread and moves
   * nothing.
   *
   * A length past the agent's 4 MiB per call is read in several calls,
   * stopping at the first short one, so it returns what one `read(2)` of a
   * regular file would.
   */
  read<T extends NodeJS.ArrayBufferView>(
    buffer: T,
    offset?: number | null,
    length?: number | null,
    position?: ReadPosition | null,
  ): Promise<FileReadResult<T>>;
  read<T extends NodeJS.ArrayBufferView>(
    buffer: T,
    options?: ReadOptions,
  ): Promise<FileReadResult<T>>;
  read<T extends NodeJS.ArrayBufferView = Buffer>(
    options?: ReadOptionsWithBuffer<T>,
  ): Promise<FileReadResult<T>>;
  async read(
    first?: NodeJS.ArrayBufferView | ReadOptionsWithBuffer<NodeJS.ArrayBufferView>,
    offsetOrOptions?: number | null | ReadOptions,
    length?: number | null,
    position?: ReadPosition | null,
  ): Promise<FileReadResult<NodeJS.ArrayBufferView>> {
    let buffer: NodeJS.ArrayBufferView;
    let options: ReadOptions;
    if (ArrayBuffer.isView(first)) {
      buffer = first;
      options =
        offsetOrOptions !== null && typeof offsetOrOptions === "object"
          ? offsetOrOptions
          : {
              offset: offsetOrOptions ?? undefined,
              length: length ?? undefined,
              position,
            };
    } else {
      buffer = first?.buffer ?? Buffer.alloc(DEFAULT_READ);
      options = first ?? {};
    }
    const offset = options.offset ?? 0;
    const bytesRead = await this.readInto(
      new Uint8Array(buffer.buffer, buffer.byteOffset + offset, buffer.byteLength - offset),
      options.length ?? buffer.byteLength - offset,
      options.position ?? null,
    );
    return { bytesRead, buffer };
  }

  private async readInto(
    target: Uint8Array,
    length: number,
    position: ReadPosition | null,
    signal?: AbortSignal,
  ): Promise<number> {
    const handle = this.live("read");
    const from = position === null || position === -1 ? -1 : Number(position);
    let done = 0;
    while (done < length) {
      const want = Math.min(length - done, MAX_IO);
      const data: Uint8Array = await this.fs.request(
        "read",
        { handle, position: from === -1 ? -1 : from + done, length: want },
        signal,
      );
      target.set(data, done);
      done += data.length;
      if (data.length < want) break;
    }
    return done;
  }

  /** Reads from the handle's position to the end of the file. */
  readFile(
    options?: ({ encoding?: null } & Abortable) | null,
  ): Promise<Buffer>;
  readFile(
    options: ({ encoding: BufferEncoding } & Abortable) | BufferEncoding,
  ): Promise<string>;
  readFile(
    options?: (ObjectEncodingOptions & Abortable) | BufferEncoding | null,
  ): Promise<string | Buffer>;
  async readFile(
    options?: (ObjectEncodingOptions & Abortable) | BufferEncoding | null,
  ): Promise<string | Buffer> {
    const { encoding, signal } = optionsOf(options);
    const handle = this.live("read");
    const parts: Buffer[] = [];
    while (true) {
      const data: Buffer = await this.fs.request("read", { handle, position: -1, length: MAX_IO }, signal);
      if (data.length === 0) break;
      parts.push(data);
    }
    const bytes = Buffer.concat(parts);
    return encoding ? bytes.toString(encoding) : bytes;
  }

  /** Lines of the file, from a {@link createReadStream}, as Node's `readLines`. */
  readLines(options?: CreateReadStreamOptions): Interface {
    return createInterface({ input: this.createReadStream(options), crlfDelay: Infinity });
  }

  /** Fills each buffer in turn, stopping at the end of the file. */
  async readv<T extends readonly NodeJS.ArrayBufferView[]>(
    buffers: T,
    position?: number | null,
  ): Promise<ReadVResult<T>> {
    let bytesRead = 0;
    for (const buffer of buffers) {
      const at = position === undefined || position === null ? null : position + bytesRead;
      const read = await this.readInto(
        new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength),
        buffer.byteLength,
        at,
      );
      bytesRead += read;
      if (read < buffer.byteLength) break;
    }
    return { bytesRead, buffers };
  }

  async stat(_options?: StatOptions & { bigint?: false }): Promise<Stats> {
    return new Stats(await this.fs.request("fstat", { handle: this.live("fstat") }));
  }

  async truncate(len = 0): Promise<void> {
    await this.fs.request("ftruncate", { handle: this.live("ftruncate"), length: len });
  }

  /** Path-based, as {@link chmod} is. */
  async utimes(atime: TimeLike, mtime: TimeLike): Promise<void> {
    this.live("futime");
    await this.fs.utimes(this.path, atime, mtime);
  }

  /**
   * Writes `buffer`, or a string in `encoding`. `position` is as for
   * {@link read}; a handle opened for append always writes at the end.
   */
  write<T extends NodeJS.ArrayBufferView>(
    buffer: T,
    offset?: number | null,
    length?: number | null,
    position?: number | null,
  ): Promise<{ bytesWritten: number; buffer: T }>;
  write<T extends NodeJS.ArrayBufferView>(
    buffer: T,
    options?: { offset?: number; length?: number; position?: number | null },
  ): Promise<{ bytesWritten: number; buffer: T }>;
  write(
    data: string,
    position?: number | null,
    encoding?: BufferEncoding | null,
  ): Promise<{ bytesWritten: number; buffer: string }>;
  async write(
    data: string | NodeJS.ArrayBufferView,
    second?: number | null | { offset?: number; length?: number; position?: number | null },
    third?: number | BufferEncoding | null,
    fourth?: number | null,
  ): Promise<{ bytesWritten: number; buffer: string | NodeJS.ArrayBufferView }> {
    if (typeof data === "string") {
      const bytes = Buffer.from(data, (third as BufferEncoding | null) ?? "utf8");
      const bytesWritten = await this.writeAll(bytes, (second as number | null) ?? null);
      return { bytesWritten, buffer: data };
    }
    const options =
      second !== null && typeof second === "object"
        ? second
        : { offset: second ?? undefined, length: (third as number | null) ?? undefined, position: fourth };
    const offset = options.offset ?? 0;
    const bytes = Buffer.from(
      data.buffer,
      data.byteOffset + offset,
      options.length ?? data.byteLength - offset,
    );
    return { bytesWritten: await this.writeAll(bytes, options.position ?? null), buffer: data };
  }

  /** Writes all of `bytes`, in calls of at most the agent's 4 MiB. */
  private async writeAll(
    bytes: Uint8Array,
    position: number | null,
    signal?: AbortSignal,
  ): Promise<number> {
    const handle = this.live("write");
    let done = 0;
    // An empty write still reaches the kernel, which is what O_CREAT and
    // the error for a handle opened read-only both depend on.
    do {
      const data = bytes.subarray(done, done + MAX_IO);
      const written: number = await this.fs.request(
        "write",
        { handle, position: position === null || position === -1 ? -1 : position + done, data },
        signal,
      );
      done += written;
    } while (done < bytes.length);
    return done;
  }

  /**
   * Writes `data` from the handle's position on, as Node's does: after
   * earlier writes it continues where they left off rather than rewriting the
   * file from the start.
   */
  async writeFile(
    data: WriteData,
    options?: (ObjectEncodingOptions & Abortable) | BufferEncoding | null,
  ): Promise<void> {
    const { encoding, signal } = optionsOf(options);
    if (typeof data === "string" || ArrayBuffer.isView(data)) {
      await this.writeAll(bytesOf(data, encoding), null, signal);
      return;
    }
    for await (const chunk of data) {
      if (signal?.aborted) throw abortError(signal);
      await this.writeAll(bytesOf(chunk, encoding), null, signal);
    }
  }

  async writev<T extends readonly NodeJS.ArrayBufferView[]>(
    buffers: T,
    position?: number | null,
  ): Promise<WriteVResult<T>> {
    let bytesWritten = 0;
    for (const buffer of buffers) {
      const at = position === undefined || position === null ? null : position + bytesWritten;
      bytesWritten += await this.writeAll(bytesOf(buffer, null), at);
    }
    return { bytesWritten, buffers };
  }

  /**
   * A `Readable` over this handle. `start` and `end` are inclusive byte
   * offsets; without `start` it reads from the handle's position. Closes the
   * handle when it ends unless `autoClose` is false.
   */
  createReadStream(options: CreateReadStreamOptions = {}): Readable {
    const end = options.end ?? Infinity;
    let position = options.start ?? (Number.isFinite(end) ? 0 : -1);
    const autoClose = options.autoClose ?? true;
    const stream: Readable = new Readable({
      highWaterMark: options.highWaterMark ?? 64 * 1024,
      encoding: options.encoding ?? undefined,
      emitClose: options.emitClose ?? true,
      signal: options.signal,
      read: (size) => {
        const want = Math.min(size, MAX_IO, position === -1 ? Infinity : end - position + 1);
        if (want <= 0) {
          stream.push(null);
          return;
        }
        const chunk = Buffer.alloc(want);
        this.readInto(chunk, want, position === -1 ? null : position).then(
          (read) => {
            if (position !== -1) position += read;
            stream.push(read ? chunk.subarray(0, read) : null);
          },
          (err) => stream.destroy(err),
        );
      },
      destroy: (err, callback) => {
        if (!autoClose) return callback(err);
        this.close().then(
          () => callback(err),
          (closeErr) => callback(err ?? closeErr),
        );
      },
    });
    return stream;
  }

  /**
   * A `Writable` over this handle, from `start` or from the handle's
   * position. `flush` syncs before the stream finishes.
   */
  createWriteStream(options: CreateWriteStreamOptions = {}): Writable {
    let position = options.start ?? -1;
    const autoClose = options.autoClose ?? true;
    return new Writable({
      highWaterMark: options.highWaterMark,
      defaultEncoding: options.encoding ?? "utf8",
      emitClose: options.emitClose ?? true,
      write: (chunk: Buffer, _encoding, callback) => {
        this.writeAll(chunk, position === -1 ? null : position).then((written) => {
          if (position !== -1) position += written;
          callback();
        }, callback);
      },
      final: (callback) => {
        if (!options.flush) return callback();
        this.sync().then(() => callback(), callback);
      },
      destroy: (err, callback) => {
        if (!autoClose) return callback(err);
        this.close().then(
          () => callback(err),
          (closeErr) => callback(err ?? closeErr),
        );
      },
    });
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }
}

/**
 * Codes a whole-file download can fail with that may be a kernel error it has
 * no way to name. The file is then read the long way, which reports the error
 * as `fs` would. Every other code, a policy refusal above all, is the answer.
 */
const DOWNLOAD_RETRIED = new Set(["not_found", "invalid_argument", "failed_precondition", "internal"]);

/**
 * The sandbox's filesystem, as `fs/promises`.
 *
 * ```ts
 * await sandbox.fs.mkdir("/work/src", { recursive: true });
 * await sandbox.fs.writeFile("/work/src/app.py", "print('hi')\n");
 * for (const entry of await sandbox.fs.readdir("/work", { withFileTypes: true })) {
 *   console.log(entry.name, entry.isDirectory());
 * }
 * ```
 *
 * Calls act as the handle's user (root, or the one {@link Sandbox.asUser}
 * named), checked by the guest kernel. Kernel errors are Node's: `code`,
 * negative `errno`, `syscall`, `path`. The file policy refuses the way the
 * kernel would: `EACCES` for a path or a direction it does not allow, `EFBIG`
 * past its write ceiling. Methods are bound, so
 * `const { readFile } = sandbox.fs` works as it does with `fs/promises`.
 */
export class SandboxFs {
  readonly constants = constants;

  /** @internal */
  constructor(private readonly guest: GuestLink) {
    for (const name of Object.getOwnPropertyNames(SandboxFs.prototype)) {
      const value = (this as any)[name];
      if (name !== "constructor" && typeof value === "function") (this as any)[name] = value.bind(this);
    }
  }

  /** @internal One `Fs` call. Resolves with what the operation returned. */
  async request(op: string, body: object, signal?: AbortSignal): Promise<any> {
    if (signal?.aborted) throw abortError(signal);
    let res: any;
    try {
      res = await this.guest.run(() =>
        this.guest.node().unary<any, any>(
          "Fs",
          { sandboxId: this.guest.sandboxId, user: this.guest.user, [op]: body },
          undefined,
          signal,
        ),
      );
    } catch (err) {
      if (signal?.aborted) throw abortError(signal);
      throw err;
    }
    if (res.result === "error") throw fsError(res.error);
    return res[res.result];
  }

  async access(path: PathLike, mode: number = constants.F_OK): Promise<void> {
    await this.request("access", { path: toPath(path), mode });
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
    await this.request("chmod", { path: toPath(path), mode: toMode(mode, 0) });
  }

  async chown(path: PathLike, uid: number, gid: number): Promise<void> {
    await this.request("chown", { path: toPath(path), uid, gid, isNofollow: false });
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
    await this.request("copy", {
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
      this.request("copy", {
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
    await this.request("chown", { path: toPath(path), uid, gid, isNofollow: true });
  }

  async link(existingPath: PathLike, newPath: PathLike): Promise<void> {
    await this.request("link", { existing: toPath(existingPath), path: toPath(newPath) });
  }

  async lstat(path: PathLike, _options?: StatOptions & { bigint?: false }): Promise<Stats> {
    return new Stats(await this.request("stat", { path: toPath(path), isNofollow: true }));
  }

  async lutimes(path: PathLike, atime: TimeLike, mtime: TimeLike): Promise<void> {
    await this.request("utimes", {
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
    const created: string | undefined = await this.request("mkdir", {
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
    return encoded(await this.request("mkdtemp", { prefix }), optionsOf(options).encoding);
  }

  /** Opens a file. Flags as Node's strings (`"r"`, `"w+"`, `"ax"`, ...) or Linux numbers. */
  async open(path: PathLike, flags?: OpenMode, mode?: Mode | null): Promise<FileHandle> {
    const resolved = toPath(path);
    const handle: number = await this.request("open", {
      path: resolved,
      flags: toFlags(flags, "r"),
      mode: toMode(mode, 0o666),
    });
    return new FileHandle(this, handle, resolved);
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
      const { entries } = await this.request("readDir", { path: dir });
      for (const entry of entries as Array<{ name: string; type: string }>) {
        let type = entry.type;
        if (type === "unknown") type = typeOf(await this.lstat(posix.join(dir, entry.name)));
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

  /**
   * Reads a whole file. A plain read as root takes the `DownloadFile` stream,
   * one call however big the file; one with a `flag`, or as a user, opens
   * and reads, so the guest kernel checks the user may.
   */
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
    const resolved = toPath(path);
    if (flags === O_RDONLY && !this.guest.user) {
      try {
        const bytes = await this.download(resolved, signal);
        return encoding ? bytes.toString(encoding) : bytes;
      } catch (err) {
        if (signal?.aborted) throw abortError(signal);
        if (!(err instanceof BurrowError) || !DOWNLOAD_RETRIED.has(err.code)) throw err;
      }
    }
    const handle = await this.open(resolved, flags);
    try {
      return await handle.readFile({ encoding: encoding ?? null, signal });
    } finally {
      await handle.close();
    }
  }

  private async download(path: string, signal?: AbortSignal): Promise<Buffer> {
    const parts: Buffer[] = [];
    await this.guest.run(async () => {
      parts.length = 0;
      for await (const chunk of this.guest.node().serverStream<any, any>(
        "DownloadFile",
        { sandboxId: this.guest.sandboxId, path },
        undefined,
        signal,
      )) {
        if (chunk.data?.length) parts.push(Buffer.from(chunk.data));
      }
    });
    return Buffer.concat(parts);
  }

  readlink(path: PathLike, options?: EncodingOption): Promise<string>;
  readlink(path: PathLike, options: BufferEncodingOption): Promise<Buffer>;
  async readlink(
    path: PathLike,
    options?: EncodingOption | BufferEncodingOption,
  ): Promise<string | Buffer> {
    return encoded(await this.request("readlink", { path: toPath(path) }), optionsOf(options).encoding);
  }

  realpath(path: PathLike, options?: EncodingOption): Promise<string>;
  realpath(path: PathLike, options: BufferEncodingOption): Promise<Buffer>;
  async realpath(
    path: PathLike,
    options?: EncodingOption | BufferEncodingOption,
  ): Promise<string | Buffer> {
    return encoded(await this.request("realpath", { path: toPath(path) }), optionsOf(options).encoding);
  }

  async rename(oldPath: PathLike, newPath: PathLike): Promise<void> {
    await this.request("rename", { src: toPath(oldPath), dst: toPath(newPath) });
  }

  /**
   * Removes a file, or with `recursive` a tree; `force` makes a missing path
   * not an error. `maxRetries` and `retryDelay` are accepted and unused: the
   * busy-file errors they retry are Windows'.
   */
  async rm(path: PathLike, options: RmOptions = {}): Promise<void> {
    await this.request("remove", {
      path: toPath(path),
      isRecursive: options.recursive ?? false,
      isForce: options.force ?? false,
      isDirOnly: false,
    });
  }

  /** Removes an empty directory. Node's deprecated `recursive` acts as {@link rm}'s. */
  async rmdir(path: PathLike, options: RmDirOptions = {}): Promise<void> {
    await this.request("remove", {
      path: toPath(path),
      isRecursive: options.recursive ?? false,
      isForce: false,
      isDirOnly: !options.recursive,
    });
  }

  /** `bigint` is not offered: times arrive from the guest as doubles already. */
  async stat(path: PathLike, _options?: StatOptions & { bigint?: false }): Promise<Stats> {
    return new Stats(await this.request("stat", { path: toPath(path), isNofollow: false }));
  }

  /** `type` is Windows' and ignored, as Node ignores it elsewhere. */
  async symlink(target: PathLike, path: PathLike, _type?: string | null): Promise<void> {
    await this.request("symlink", { target: toPath(target), path: toPath(path) });
  }

  async truncate(path: PathLike, len = 0): Promise<void> {
    await this.request("truncate", { path: toPath(path), length: len });
  }

  async unlink(path: PathLike): Promise<void> {
    await this.request("remove", {
      path: toPath(path),
      isRecursive: false,
      isForce: false,
      isDirOnly: false,
    });
  }

  /** Times as a `Date`, seconds since the epoch, or a numeric string of them. */
  async utimes(path: PathLike, atime: TimeLike, mtime: TimeLike): Promise<void> {
    await this.request("utimes", {
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
   * for await (const { eventType, filename } of sandbox.fs.watch("/work", { signal: ac.signal })) {
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
          eventType: raw.type === "modified" ? "change" : "rename",
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
}
