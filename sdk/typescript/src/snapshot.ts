import { BurrowError } from "./errors.js";
import { Transport, type TransportOptions } from "./transport.js";

/** Options for taking a snapshot of a sandbox. */
export interface SnapshotOptions {
  /**
   * Seconds from last use before the snapshot is swept, where a use is a
   * sandbox created from it. Omitted falls back to the sandbox's
   * `resources.snapshotExpirationSecs`, and to no expiry when that is 0 too.
   */
  expiration?: number;
  signal?: AbortSignal;
}

/** Options for {@link Snapshot.list}. */
export interface ListSnapshotsOptions {
  /** Only snapshots taken of this sandbox, by id or name. */
  sandbox?: string;
}

/**
 * A sandbox's saved state, addressable on its own.
 *
 * Obtained from {@link Sandbox.snapshot}, {@link Snapshot.get} or
 * {@link Snapshot.list}; not constructed directly.
 *
 * ```ts
 * const snapshot = await prepared.snapshot({ expiration: 86_400 });
 * await prepared.delete();
 *
 * // Outlives its source, and starts any number of sandboxes by restoring.
 * const worker = await Sandbox.create({ snapshot: snapshot.id });
 * ```
 *
 * A snapshot encodes the host's cpu architecture and the exact Firecracker
 * version. A create from one is placed on the node holding it. When the nodes
 * run with an object store, the snapshot is also uploaded there and
 * {@link isDurable} turns true; a create from a durable snapshot can then be
 * placed on any node with the same {@link arch} and {@link firecrackerVersion},
 * including when the node that took it is gone.
 */
export class Snapshot {
  readonly id: string;
  /** The sandbox the state was taken from. It may since have been deleted. */
  readonly sandboxId: string;
  readonly template: string;
  /**
   * The node holding it locally. Empty when only the object store holds it.
   */
  readonly nodeId: string;
  /** The machine the snapshot was taken on, and the only one it restores as. */
  readonly vcpus: number;
  readonly memoryMib: number;
  readonly diskMib: number;
  /** RFC 3339. */
  readonly createdAt: string;
  /** Memory image, vmstate and scratch disk, as the node's disk sees them. */
  readonly sizeBytes: number;
  /** RFC 3339, or `""` when the snapshot does not expire. */
  readonly expiresAt: string;
  /**
   * A copy is in the fleet's object store, so a create from it can be placed
   * on any node matching {@link arch} and {@link firecrackerVersion}.
   */
  readonly isDurable: boolean;
  /** Cpu architecture it was taken on. */
  readonly arch: string;
  /** Firecracker version it was taken with. */
  readonly firecrackerVersion: string;

  private readonly transport: Transport;

  private constructor(transport: Transport, raw: any) {
    if (!raw.id) {
      throw new BurrowError("server returned a snapshot with no id", "internal");
    }
    this.transport = transport;
    this.id = String(raw.id);
    this.sandboxId = String(raw.sandboxId ?? "");
    this.template = String(raw.template ?? "");
    this.nodeId = String(raw.nodeId ?? "");
    this.vcpus = Number(raw.vcpus ?? 0);
    this.memoryMib = Number(raw.memMib ?? 0);
    this.diskMib = Number(raw.scratchDiskMib ?? 0);
    this.createdAt = String(raw.createdAt ?? "");
    this.sizeBytes = Number(raw.sizeBytes ?? 0);
    this.expiresAt = String(raw.expiresAt ?? "");
    this.isDurable = Boolean(raw.isDurable);
    this.arch = String(raw.arch ?? "");
    this.firecrackerVersion = String(raw.firecrackerVersion ?? "");
  }

  /** @internal: lets a sandbox hand its own connection to the snapshot. */
  static adopt(transport: Transport, raw: any): Snapshot {
    return new Snapshot(transport, raw);
  }

  /** Returns a handle for a snapshot that already exists. */
  static async get(
    id: string,
    options: TransportOptions & { signal?: AbortSignal } = {},
  ): Promise<Snapshot> {
    const transport = new Transport(options);
    try {
      const raw = await transport.unary<any, any>(
        "GetSnapshot",
        { id },
        options.timeoutMs,
        options.signal,
      );
      return new Snapshot(transport, raw);
    } catch (err) {
      transport.close();
      throw err;
    }
  }

  /**
   * Lists snapshots, newest first.
   *
   * ```ts
   * for (const snapshot of await Snapshot.list({ sandbox: "build-482" })) {
   *   await snapshot.delete();
   * }
   * ```
   */
  static async list(
    options: ListSnapshotsOptions & TransportOptions & { signal?: AbortSignal } = {},
  ): Promise<Snapshot[]> {
    const transport = new Transport(options);
    try {
      const res = await transport.unary<any, any>(
        "ListSnapshots",
        { sandbox: options.sandbox ?? "" },
        options.timeoutMs,
        options.signal,
      );
      // Retained per handle, so releasing one does not close the channel the
      // others still hold.
      return (res.snapshots ?? []).map((raw: any) =>
        new Snapshot(transport.retain(), raw),
      );
    } finally {
      transport.close();
    }
  }

  /** Deletes a snapshot, from the node holding it and from the object store. */
  async delete(options: { signal?: AbortSignal } = {}): Promise<void> {
    try {
      await this.transport.unary(
        "DeleteSnapshot",
        { id: this.id },
        this.transport.timeoutMs,
        options.signal,
      );
    } finally {
      this.transport.close();
    }
  }

  /** Releases this handle's share of the connection. */
  close(): void {
    this.transport.close();
  }
}
