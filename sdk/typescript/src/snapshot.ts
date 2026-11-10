import { withClient } from "./client.js";
import { BurrowError } from "./errors.js";
import { fromResourcePolicy } from "./policy.js";
import type { Transport, TransportOptions } from "./transport.js";
import type { CallOptions, ResourcePolicy } from "./types.js";
import { dateOf, dateOrNull } from "./wire.js";

/** Options for taking a snapshot of a sandbox. */
export interface SnapshotOptions extends CallOptions {
  /**
   * Seconds from last use before the snapshot is swept, where a use is a
   * sandbox created from it. Omitted falls back to the sandbox's
   * `snapshots.expirationSecs`, and to no expiry when that is 0 too.
   */
  expirationSecs?: number;
}

/** Options for {@link Snapshot.list}. */
export interface ListSnapshotsOptions extends CallOptions {
  /** Only snapshots taken of this sandbox, by id or name. */
  sandboxId?: string;
}

/**
 * A sandbox's saved state, addressable on its own.
 *
 * Obtained from {@link Sandbox.snapshot}, {@link Snapshot.get} or
 * {@link Snapshot.list}; not constructed directly.
 *
 * ```ts
 * const snapshot = await prepared.snapshot({ expirationSecs: 86_400 });
 * await prepared.delete();
 *
 * // Outlives its source, and starts any number of sandboxes by restoring.
 * const worker = await Sandbox.create({ snapshot: snapshot.id });
 * ```
 *
 * A snapshot encodes the host's cpu architecture and the exact hypervisor
 * version. A create from one is placed on the node holding it. When the nodes
 * run with an object store, the snapshot is also uploaded there and
 * {@link durable} turns true; a create from a durable snapshot can then be
 * placed on any node with the same {@link arch}, {@link hypervisor} and
 * {@link hypervisorVersion}, including when the node that took it is gone.
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
  readonly resources: ResourcePolicy;
  readonly createdAt: Date;
  /** Memory image, vmstate and scratch disk, as the node's disk sees them. */
  readonly sizeBytes: number;
  /** `null` when the snapshot does not expire. */
  readonly expiresAt: Date | null;
  /**
   * A copy is in the fleet's object store, so a create from it can be placed
   * on any node matching {@link arch} and {@link hypervisorVersion}.
   */
  readonly durable: boolean;
  /** Cpu architecture it was taken on. */
  readonly arch: string;
  /** The hypervisor that took it, and the version it restores under. */
  readonly hypervisor: string;
  readonly hypervisorVersion: string;

  private readonly transport: Transport;

  /** @internal */
  constructor(transport: Transport, raw: any) {
    if (!raw.id) {
      throw new BurrowError("server returned a snapshot with no id", "internal");
    }
    this.transport = transport;
    this.id = String(raw.id);
    this.sandboxId = String(raw.sandboxId ?? "");
    this.template = String(raw.template ?? "");
    this.nodeId = String(raw.nodeId ?? "");
    this.resources = fromResourcePolicy(raw.resources);
    this.createdAt = dateOf(raw.createdAtUnixMs);
    this.sizeBytes = Number(raw.sizeBytes ?? 0);
    this.expiresAt = dateOrNull(raw.expiresAtUnixMs);
    this.durable = Boolean(raw.isDurable);
    this.arch = String(raw.arch ?? "");
    this.hypervisor = String(raw.hypervisor ?? "");
    this.hypervisorVersion = String(raw.hypervisorVersion ?? "");
  }

  /** Returns a handle for a snapshot that already exists. */
  static get(id: string, options: TransportOptions & CallOptions = {}): Promise<Snapshot> {
    return withClient(options, (burrow) => burrow.snapshots.get(id, options));
  }

  /**
   * Lists snapshots, newest first.
   *
   * ```ts
   * for (const snapshot of await Snapshot.list({ sandboxId: "build-482" })) {
   *   await snapshot.delete();
   * }
   * ```
   */
  static list(options: ListSnapshotsOptions & TransportOptions = {}): Promise<Snapshot[]> {
    return withClient(options, (burrow) => burrow.snapshots.list(options));
  }

  /** Deletes a snapshot, from the node holding it and from the object store. */
  async delete(options: CallOptions = {}): Promise<void> {
    await this.transport.unary(
      "DeleteSnapshot",
      { id: this.id },
      options.timeoutMs,
      options.signal,
    );
    this.transport.close();
  }

  /** Releases this handle's share of the connection. */
  close(): void {
    this.transport.close();
  }
}
