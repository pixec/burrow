import { BurrowError } from "./errors.js";
import { Transport, type TransportOptions } from "./transport.js";

/** Options for {@link Volume.create}. */
export interface CreateVolumeOptions {
  /** Size of the image in MiB, 1 to 1048576. Defaults to 1024. */
  sizeMib?: number;
  /**
   * Labels the node holding it must carry, all of them.
   *
   * A volume never moves, so this is the only chance to influence where it
   * lands, and where every sandbox that mounts it will therefore run.
   */
  nodeLabels?: Record<string, string>;
  signal?: AbortSignal;
}

/** Options for {@link Volume.list}. */
export interface ListVolumesOptions {
  /** Only volumes on this node. */
  node?: string;
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
  /** RFC 3339. */
  readonly createdAt: string;
  /** Sandbox holding the writable claim, or `""` when free. */
  readonly attachedTo: string;

  private readonly transport: Transport;

  private constructor(transport: Transport, raw: any) {
    if (!raw.name) {
      throw new BurrowError("server returned a volume with no name", "internal");
    }
    this.transport = transport;
    this.name = String(raw.name);
    this.nodeId = String(raw.nodeId ?? "");
    this.sizeMib = Number(raw.sizeMib ?? 0);
    this.createdAt = String(raw.createdAt ?? "");
    this.attachedTo = String(raw.attachedTo ?? "");
  }

  /** Creates a volume, placing it on a node that satisfies `nodeLabels`. */
  static async create(
    name: string,
    options: CreateVolumeOptions & TransportOptions = {},
  ): Promise<Volume> {
    const transport = new Transport(options);
    try {
      const raw = await transport.unary<any, any>(
        "CreateVolume",
        {
          name,
          sizeMib: options.sizeMib ?? 1024,
          nodeLabels: options.nodeLabels ?? {},
        },
        options.timeoutMs,
        options.signal,
      );
      return new Volume(transport, raw);
    } catch (err) {
      transport.close();
      throw err;
    }
  }

  /**
   * Returns a handle for a volume that already exists.
   *
   * Read from the node holding it, so {@link attachedTo} is current rather
   * than whatever the orchestrator last cached.
   */
  static async get(
    name: string,
    options: TransportOptions & { signal?: AbortSignal } = {},
  ): Promise<Volume> {
    const transport = new Transport(options);
    try {
      const raw = await transport.unary<any, any>(
        "GetVolume",
        { name },
        options.timeoutMs,
        options.signal,
      );
      return new Volume(transport, raw);
    } catch (err) {
      transport.close();
      throw err;
    }
  }

  /** Lists volumes by name. */
  static async list(
    options: ListVolumesOptions & TransportOptions & { signal?: AbortSignal } = {},
  ): Promise<Volume[]> {
    const transport = new Transport(options);
    try {
      const res = await transport.unary<any, any>(
        "ListVolumes",
        { nodeId: options.node ?? "" },
        options.timeoutMs,
        options.signal,
      );
      // Retained per handle, so releasing one does not close the channel the
      // others still hold.
      return (res.volumes ?? []).map((raw: any) =>
        new Volume(transport.retain(), raw),
      );
    } finally {
      transport.close();
    }
  }

  /**
   * Deletes the volume and everything stored in it.
   *
   * Refused while a sandbox holds it writable; stop that sandbox first.
   */
  async delete(options: { signal?: AbortSignal } = {}): Promise<void> {
    try {
      await this.transport.unary(
        "DeleteVolume",
        { name: this.name },
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
