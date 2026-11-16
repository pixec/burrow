/**
 * What the sandbox's `fs/promises` methods return and are built on: `Stats`,
 * `Dirent`, `FileHandle`, and the `Fs` call itself.
 *
 * Every call is one `Fs` RPC carrying one POSIX operation, so the semantics
 * are the kernel's own: what `open(2)` would refuse is refused, with the errno
 * it would have set.
 */

import { Buffer } from "node:buffer";
import type { Abortable } from "node:events";
import type {
  Dirent as NodeDirent,
  Mode,
  ObjectEncodingOptions,
  OpenMode,
  PathLike,
  ReadOptions,
  ReadOptionsWithBuffer,
  ReadPosition,
  ReadVResult,
  Stats as NodeStats,
  StatOptions,
  TimeLike,
  WatchOptions as NodeWatchOptions,
  WriteVResult,
} from "node:fs";
import type {
  CreateReadStreamOptions,
  CreateWriteStreamOptions,
  FileReadResult,
} from "node:fs/promises";
import { createInterface, type Interface } from "node:readline";
import { Readable, Writable } from "node:stream";
import { getSystemErrorMap, inspect } from "node:util";

import { BurrowError } from "./errors.js";
import type { GuestLink } from "./guest.js";
import { MAX_FILE_CHUNK } from "./transport.js";

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

/** @internal A guest kernel error, shaped exactly as Node's own `fs` reports one. */
export function fsError(raw: any): SystemError {
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

/** @internal Node's `AbortError`, which an aborted `fs` call rejects with. */
export function abortError(signal: AbortSignal): Error {
  return Object.assign(new Error("The operation was aborted", { cause: signal.reason }), {
    name: "AbortError",
    code: "ABORT_ERR",
  });
}

/** @internal */
export function invalidArgValue(name: string, value: unknown): TypeError {
  return Object.assign(
    new TypeError(`The argument '${name}' is invalid. Received ${inspect(value)}`),
    { code: "ERR_INVALID_ARG_VALUE" },
  );
}

/** @internal */
export function toFlags(flags: OpenMode | null | undefined, fallback: string): number {
  if (flags === undefined || flags === null) return FLAGS[fallback]!;
  if (typeof flags === "number") return flags;
  const value = FLAGS[flags];
  if (value === undefined) throw invalidArgValue("flags", flags);
  return value;
}

/** @internal */
export function toMode(mode: Mode | null | undefined, fallback: number): number {
  if (mode === undefined || mode === null) return fallback;
  return typeof mode === "string" ? parseInt(mode, 8) : mode;
}

/** @internal A guest path. A `file:` URL is its pathname, as Node reads one. */
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
 * @internal Nanoseconds since the epoch, as a decimal string: a number cannot
 * hold them exactly, and the wire field is 64-bit. Node's coercion: a number
 * or numeric string is seconds, and a time that is not finite means now.
 */
export function toNanos(time: TimeLike): string {
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

export type Encoding = BufferEncoding | "buffer" | null | undefined;

/** @internal Options as Node takes them: an encoding name stands for `{ encoding }`. */
export function optionsOf<T extends object>(
  options: T | BufferEncoding | "buffer" | null | undefined,
): Partial<T> & { encoding?: Encoding } {
  return typeof options === "string"
    ? ({ encoding: options } as Partial<T> & { encoding: Encoding })
    : (options ?? {});
}

/** @internal A name or path in the encoding asked for. The wire carries UTF-8. */
export function encoded(value: string, encoding: Encoding): string | Buffer {
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

/** @internal The d_type name a `Stats` corresponds to, for entries d_type left unknown. */
export function typeOf(stats: Stats): string {
  if (stats.isFile()) return "file";
  if (stats.isDirectory()) return "dir";
  if (stats.isSymbolicLink()) return "symlink";
  if (stats.isFIFO()) return "fifo";
  if (stats.isSocket()) return "socket";
  if (stats.isCharacterDevice()) return "char";
  if (stats.isBlockDevice()) return "block";
  return "unknown";
}

export type WriteData =
  | string
  | NodeJS.ArrayBufferView
  | Iterable<string | NodeJS.ArrayBufferView>
  | AsyncIterable<string | NodeJS.ArrayBufferView>;

export type ReadFileOptions = ObjectEncodingOptions & Abortable & { flag?: OpenMode };

export type WriteFileOptions = ObjectEncodingOptions &
  Abortable & { mode?: Mode; flag?: OpenMode; flush?: boolean };

/** `Sandbox.watch`'s options: Node's, plus the guest's poll interval. */
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
    private readonly guest: GuestLink,
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
    await fsRequest(this.guest, "chmod", { path: this.path, mode: toMode(mode, 0) });
  }

  /** Path-based, as {@link chmod} is. */
  async chown(uid: number, gid: number): Promise<void> {
    this.live("fchown");
    await fsRequest(this.guest, "chown", { path: this.path, uid, gid, isNofollow: false });
  }

  async close(): Promise<void> {
    const handle = this.handle;
    if (handle === -1) return;
    this.handle = -1;
    await fsRequest(this.guest, "close", { handle });
  }

  async datasync(): Promise<void> {
    await fsRequest(this.guest, "fsync", { handle: this.live("fdatasync"), isDataOnly: true });
  }

  async sync(): Promise<void> {
    await fsRequest(this.guest, "fsync", { handle: this.live("fsync"), isDataOnly: false });
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
      const want = Math.min(length - done, MAX_FILE_CHUNK);
      const data: Uint8Array = await fsRequest(this.guest, 
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
      const data: Buffer = await fsRequest(this.guest, "read", { handle, position: -1, length: MAX_FILE_CHUNK }, signal);
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
    return new Stats(await fsRequest(this.guest, "fstat", { handle: this.live("fstat") }));
  }

  async truncate(len = 0): Promise<void> {
    await fsRequest(this.guest, "ftruncate", { handle: this.live("ftruncate"), length: len });
  }

  /** Path-based, as {@link chmod} is. */
  async utimes(atime: TimeLike, mtime: TimeLike): Promise<void> {
    this.live("futime");
    await fsRequest(this.guest, "utimes", {
      path: this.path,
      atimeNs: toNanos(atime),
      mtimeNs: toNanos(mtime),
      isNofollow: false,
    });
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
      const data = bytes.subarray(done, done + MAX_FILE_CHUNK);
      const written: number = await fsRequest(this.guest, 
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
        const want = Math.min(size, MAX_FILE_CHUNK, position === -1 ? Infinity : end - position + 1);
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

/** @internal One `Fs` call as `guest`'s user. Resolves with what the operation returned. */
export async function fsRequest(guest: GuestLink, op: string, body: object, signal?: AbortSignal): Promise<any> {
  if (signal?.aborted) throw abortError(signal);
  let res: any;
  try {
    res = await guest.run(() =>
      guest.node().unary<any, any>(
        "Fs",
        { sandboxId: guest.sandboxId, user: guest.user, [op]: body },
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
