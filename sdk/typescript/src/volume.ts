import { withClient } from "./client.js";
import { BurrowError } from "./errors.js";
import type { Transport, TransportOptions } from "./transport.js";
import type { CallOptions } from "./types.js";
import { dateOf } from "./wire.js";

/** Options for {@link Volume.create}. */
export interface CreateVolumeOptions extends CallOptions {
  /** Size of the image in MiB, 1 to 1048576. Defaults to 1024. */
  sizeMib?: number;
  /**
   * Labels the node holding it must carry, all of them.
   *
   * A volume never moves, so this is the only chance to influence where it
   * lands, and where every sandbox that mounts it will therefore run.
   */
  nodeLabels?: Record<string, string>;
  /** Free-form key/value pairs recorded on the volume. */
  labels?: Record<string, string>;
}

/** Options for {@link Volume.list}. */
export interface ListVolumesOptions extends CallOptions {
  /** Only volumes on this node. */
  nodeId?: string;
}

/**
 * Storage that outlives the sandboxes mounting it.
 *
 * ```ts
 * const cache = await Volume.create("build-cache", { sizeMib: 20_480 });
 * const sbx = await Sandbox.create({
 *   template: "python",
 *   volumes: [{ volume: "build-cache", path: "/cache" }],
 * });
 * ```
 *
 * A volume is an ext4 image on one node, attached to the guest as a block
 * device. Three things follow from that, and none of them are avoidable:
 *
 * - **Writable mounts are exclusive.** ext4 is not a cluster filesystem, so one
 *   sandbox at a time may mount a volume read-write. The claim is released when
 *   that sandbox stops.
 * - **Read-only mounts are shared.** Any number of sandboxes may mount one
 *   read-only at once, even alongside the writer.
 * - **A volume never moves.** A sandbox that mounts one is placed on the node
 *   holding it, and mounting one costs a cold boot rather than a warm restore.
 */
export class Volume {
  readonly name: string;
  /** The node holding it, and the only node it can be attached on. */
  readonly nodeId: string;
  readonly sizeMib: number;
  readonly createdAt: Date;
  /** Sandbox holding the writable claim, or `""` when free. */
  readonly attachedTo: string;
  readonly labels: Record<string, string>;

  private readonly transport: Transport;

  /** @internal */
  constructor(transport: Transport, raw: any) {
    if (!raw.name) {
      throw new BurrowError("server returned a volume with no name", "internal");
    }
    this.transport = transport;
    this.name = String(raw.name);
    this.nodeId = String(raw.nodeId ?? "");
    this.sizeMib = Number(raw.sizeMib ?? 0);
    this.createdAt = dateOf(raw.createdAtUnixMs);
    this.attachedTo = String(raw.attachedTo ?? "");
    this.labels = raw.labels ?? {};
  }

  /** Creates a volume, placing it on a node that satisfies `nodeLabels`. */
  static create(
    name: string,
    options: CreateVolumeOptions & TransportOptions = {},
  ): Promise<Volume> {
    return withClient(options, (burrow) => burrow.volumes.create(name, options));
  }

  /**
   * Returns a handle for a volume that already exists.
   *
   * Read from the node holding it, so {@link attachedTo} is current rather
   * than whatever the orchestrator last cached.
   */
  static get(name: string, options: TransportOptions & CallOptions = {}): Promise<Volume> {
    return withClient(options, (burrow) => burrow.volumes.get(name, options));
  }

  /** Lists volumes by name. */
  static list(options: ListVolumesOptions & TransportOptions = {}): Promise<Volume[]> {
    return withClient(options, (burrow) => burrow.volumes.list(options));
  }

  /**
   * Deletes the volume and everything stored in it.
   *
   * Refused while a sandbox holds it writable; stop that sandbox first.
   */
  async delete(options: CallOptions = {}): Promise<void> {
    await this.transport.unary(
      "DeleteVolume",
      { name: this.name },
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
