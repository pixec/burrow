import type { Transport } from "./transport.js";
import type {
  AllocateIpOptions,
  CallOptions,
  IpPool,
  IpProvider,
  ListIpsOptions,
  PublicIp,
} from "./types.js";
import { dateOf, dateOrNull, enumOf, enumTo } from "./wire.js";

const PROVIDERS: readonly IpProvider[] = ["static", "ovh", "hetzner", "bgp"];
const IP_STATES: readonly ("allocated" | "quarantined")[] = ["allocated", "quarantined"];

/** @internal One `PublicIp` record as the SDK reports it. */
export function toPublicIp(raw: any): PublicIp {
  return {
    address: raw?.address ?? "",
    family: Number(raw?.family ?? 0),
    prefixLen: Number(raw?.prefixLen ?? 0),
    pool: raw?.pool ?? "",
    provider: enumOf(raw?.provider, "IP_PROVIDER_", PROVIDERS),
    movable: Boolean(raw?.isMovable),
    state: enumOf(raw?.state, "PUBLIC_IP_STATE_", IP_STATES),
    sandboxId: raw?.sandboxId ?? "",
    nodeId: raw?.nodeId ?? "",
    rdns: raw?.rdns ?? "",
    allocatedAt: dateOf(raw?.allocatedAtUnixMs),
    attachedAt: dateOrNull(raw?.attachedAtUnixMs),
    quarantinedUntil: dateOrNull(raw?.quarantinedUntilUnixMs),
  };
}

function toWirePool(pool: IpPool): any {
  return {
    name: pool.name,
    nodeId: pool.nodeId ?? "",
    nodeLabels: pool.nodeLabels ?? {},
    provider: enumTo("IP_PROVIDER_", pool.provider ?? "static"),
    ranges: pool.ranges ?? [],
    addresses: pool.addresses ?? [],
    gateway: pool.gateway ?? "",
    prefixLen: pool.prefixLen ?? 0,
    nameservers: pool.nameservers ?? [],
    prefix6: pool.prefix6 ?? "",
    perSandbox: pool.perSandbox ?? 0,
    isOnLink: pool.onLink ?? false,
    isSmtpAllowed: pool.allowSmtp ?? false,
    isWakeOnTraffic: pool.wakeOnTraffic ?? false,
    quarantineSecs: pool.quarantineSecs ?? 0,
  };
}

function toPool(raw: any): IpPool {
  const provider = enumOf(raw?.provider, "IP_PROVIDER_", PROVIDERS);
  return {
    name: raw?.name ?? "",
    nodeId: raw?.nodeId ?? "",
    nodeLabels: raw?.nodeLabels ?? {},
    provider: provider === "unknown" ? "static" : provider,
    ranges: raw?.ranges ?? [],
    addresses: raw?.addresses ?? [],
    gateway: raw?.gateway ?? "",
    prefixLen: Number(raw?.prefixLen ?? 0),
    nameservers: raw?.nameservers ?? [],
    prefix6: raw?.prefix6 ?? "",
    perSandbox: Number(raw?.perSandbox ?? 0),
    onLink: Boolean(raw?.isOnLink),
    allowSmtp: Boolean(raw?.isSmtpAllowed),
    wakeOnTraffic: Boolean(raw?.isWakeOnTraffic),
    quarantineSecs: Number(raw?.quarantineSecs ?? 0),
    total: Number(raw?.total ?? 0),
    allocated: Number(raw?.allocated ?? 0),
  };
}

/**
 * Dedicated public IPs, through one client's connection.
 *
 * ```ts
 * const ip = await burrow.ips.allocate({ sandboxId: "api" });
 * await burrow.ips.setRdns(ip.address, "mail.example.com");
 * ```
 *
 * An address is kept until released, whatever happens to the sandbox holding
 * it, and a released one is quarantined before anyone gets it again.
 */
export class Ips {
  /** @internal */
  constructor(private readonly transport: Transport) {}

  async allocate(options: AllocateIpOptions = {}): Promise<PublicIp> {
    const raw = await this.transport.unary<any, any>(
      "AllocateIp",
      {
        pool: options.pool ?? "",
        family: options.family ?? 4,
        sandboxId: options.sandboxId ?? "",
      },
      options.timeoutMs,
      options.signal,
    );
    return toPublicIp(raw);
  }

  async release(address: string, options: CallOptions = {}): Promise<void> {
    await this.transport.unary("ReleaseIp", { address }, options.timeoutMs, options.signal);
  }

  /** Routes an address to a sandbox, by id or name. */
  async attach(address: string, sandboxId: string, options: CallOptions = {}): Promise<PublicIp> {
    const raw = await this.transport.unary<any, any>(
      "AttachIp",
      { address, sandboxId },
      options.timeoutMs,
      options.signal,
    );
    return toPublicIp(raw);
  }

  /** Takes an address off its sandbox, keeping it allocated. */
  async detach(address: string, options: CallOptions = {}): Promise<PublicIp> {
    const raw = await this.transport.unary<any, any>(
      "DetachIp",
      { address },
      options.timeoutMs,
      options.signal,
    );
    return toPublicIp(raw);
  }

  /** Through the address's provider; refused for a static pool. */
  async setRdns(address: string, name: string, options: CallOptions = {}): Promise<PublicIp> {
    const raw = await this.transport.unary<any, any>(
      "SetIpRdns",
      { address, name },
      options.timeoutMs,
      options.signal,
    );
    return toPublicIp(raw);
  }

  /** The addresses this credential holds; an operator sees all. */
  async list(options: ListIpsOptions = {}): Promise<PublicIp[]> {
    const res = await this.transport.unary<any, any>(
      "ListIps",
      {
        pool: options.pool ?? "",
        sandboxId: options.sandboxId ?? "",
        isQuarantineIncluded: options.quarantined ?? false,
      },
      options.timeoutMs,
      options.signal,
    );
    return (res?.ips ?? []).map(toPublicIp);
  }

  /** Operator credentials only, as are the other pool calls. */
  async createPool(pool: IpPool, options: CallOptions = {}): Promise<IpPool> {
    const raw = await this.transport.unary<any, any>(
      "CreateIpPool",
      toWirePool(pool),
      options.timeoutMs,
      options.signal,
    );
    return toPool(raw);
  }

  /** Replaces a pool's definition; its allocated addresses must stay in it. */
  async updatePool(pool: IpPool, options: CallOptions = {}): Promise<IpPool> {
    const raw = await this.transport.unary<any, any>(
      "UpdateIpPool",
      toWirePool(pool),
      options.timeoutMs,
      options.signal,
    );
    return toPool(raw);
  }

  async deletePool(name: string, options: CallOptions = {}): Promise<void> {
    await this.transport.unary("DeleteIpPool", { name }, options.timeoutMs, options.signal);
  }

  async listPools(options: CallOptions = {}): Promise<IpPool[]> {
    const res = await this.transport.unary<any, any>(
      "ListIpPools",
      {},
      options.timeoutMs,
      options.signal,
    );
    return (res?.pools ?? []).map(toPool);
  }
}
