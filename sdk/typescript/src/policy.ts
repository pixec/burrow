/**
 * Policy conversion between the SDK's flat options and the wire shape
 * `burrow.common.v1.Policy`, so nothing else assembles proto objects inline.
 */

import { BurrowError } from "./errors.js";
import type {
  AppliedRule,
  ExecOptions,
  ExecPolicy,
  FsOptions,
  FsPolicy,
  IngressRule,
  KitOptions,
  LifetimeOptions,
  LifetimePolicy,
  NetworkInput,
  NetworkMembership,
  NetworkMode,
  NetworkPolicy,
  NetworkPolicyOptions,
  PortRule,
  RequestMatch,
  RequestRule,
  ResourceOptions,
  ResourcePolicy,
  SandboxPolicy,
  SnapshotPolicy,
  SnapshotPolicyOptions,
  StringMatch,
  VolumeMount,
} from "./types.js";
import { enumOf, enumTo } from "./wire.js";

const MODES: readonly NetworkMode[] = ["none", "allowlist", "open"];
const MODE_PREFIX = "NETWORK_MODE_";

/** A bare mode stands for a policy with only that mode set. */
export function resolveNetwork(network: NetworkInput | undefined): NetworkPolicyOptions {
  if (typeof network === "string") return { mode: network };
  return network ?? {};
}

/** Everything burrow understands on a rule. */
const RULE_KEYS = new Set(["domain", "match", "setHeaders", "forward", "expiresAt"]);

/** Every dimension a matcher may name. */
const MATCH_KEYS = new Set(["path", "method", "queryString", "headers"]);

/**
 * Refuses a key burrow does not implement, rather than dropping it.
 *
 * TypeScript rejects these at compile time, so this is for JavaScript callers.
 * It earns its place because dropping a `match` dimension would widen a
 * credential from one path and method to every request to the domain.
 */
function checkKeys(where: string, rule: RequestRule): void {
  for (const key of Object.keys(rule)) {
    if (RULE_KEYS.has(key)) continue;
    throw new BurrowError(
      `${where}: unknown key ${JSON.stringify(key)} in a rule for ${rule.domain}`,
      "invalid_argument",
    );
  }
  for (const key of Object.keys(rule.match ?? {})) {
    if (MATCH_KEYS.has(key)) continue;
    throw new BurrowError(
      `${where}: unknown key ${JSON.stringify(key)} in a match. Burrow matches on path, method, queryString and headers.`,
      "invalid_argument",
    );
  }
}

const OPS = ["exact", "startsWith", "regex"] as const;
const OP_TO_WIRE: Record<string, string> = {
  exact: "STRING_MATCH_OP_EXACT",
  startsWith: "STRING_MATCH_OP_STARTS_WITH",
  regex: "STRING_MATCH_OP_REGEX",
};
const OP_FROM_WIRE: Record<string, (typeof OPS)[number]> = {
  STRING_MATCH_OP_EXACT: "exact",
  STRING_MATCH_OP_STARTS_WITH: "startsWith",
  STRING_MATCH_OP_REGEX: "regex",
};

/** Builds one wire `StringMatch`. A bare string is the exact match it reads as. */
function toStringMatch(where: string, value: StringMatch): any {
  if (typeof value === "string") {
    return { op: OP_TO_WIRE.exact, value };
  }
  if (!value || typeof value !== "object") {
    throw new BurrowError(
      `${where}: a match is a string or one of { exact, startsWith, regex }`,
      "invalid_argument",
    );
  }
  const keys = Object.keys(value);
  const named = keys.filter((key) => key in OP_TO_WIRE);
  if (named.length !== 1 || keys.length !== 1) {
    throw new BurrowError(
      `${where}: a match names exactly one of exact, startsWith or regex`,
      "invalid_argument",
    );
  }
  const op = named[0]!;
  const pattern = (value as Record<string, unknown>)[op];
  if (typeof pattern !== "string") {
    throw new BurrowError(`${where}: a match pattern is a string`, "invalid_argument");
  }
  return { op: OP_TO_WIRE[op], value: pattern };
}

function toFieldMatches(
  where: string,
  fields: Record<string, StringMatch> | undefined,
): any[] {
  return Object.entries(fields ?? {}).map(([key, value]) => ({
    key,
    value: toStringMatch(`${where}[${JSON.stringify(key)}]`, value),
  }));
}

function toRequestMatch(where: string, match: RequestMatch | undefined): any {
  if (!match) return undefined;
  const method = match.method;
  return {
    path: match.path === undefined ? undefined : toStringMatch(`${where}.path`, match.path),
    methods: method === undefined ? [] : Array.isArray(method) ? method : [method],
    query: toFieldMatches(`${where}.queryString`, match.queryString),
    headers: toFieldMatches(`${where}.headers`, match.headers),
  };
}

/** Builds one wire `RequestRule`. */
function toRequestRule(rule: RequestRule): any {
  const where = `networkPolicy.rules[${JSON.stringify(rule.domain)}]`;
  checkKeys(where, rule);
  if (rule.setHeaders && rule.forward) {
    throw new BurrowError(
      `${where}: a rule either sets headers or forwards, not both`,
      "invalid_argument",
    );
  }
  const expiresAt = rule.expiresAt === undefined ? 0 : rule.expiresAt.getTime();
  if (!Number.isSafeInteger(expiresAt) || expiresAt < 0) {
    throw new BurrowError(`${where}: expiresAt is a valid Date`, "invalid_argument");
  }
  const wire: any = {
    domain: rule.domain,
    match: toRequestMatch(where, rule.match),
  };
  // Left off when unset, which the wire reads as never.
  if (expiresAt) wire.expiresAtUnixMs = expiresAt;
  if (rule.forward) {
    checkForwardURL(where, rule.forward.url);
    wire.forward = {
      url: rule.forward.url,
      secret: rule.forward.secret ?? "",
    };
  } else if (rule.setHeaders) {
    if (Object.keys(rule.setHeaders).length === 0) {
      throw new BurrowError(`${where}: setHeaders names no header`, "invalid_argument");
    }
    wire.setHeaders = {
      headers: Object.entries(rule.setHeaders).map(([name, value]) => {
        checkHeaderName(where, name);
        return { name, value };
      }),
    };
  } else {
    throw new BurrowError(
      `${where}: a rule needs either setHeaders or forward`,
      "invalid_argument",
    );
  }
  return wire;
}

/**
 * Refuses a forward URL burrow would refuse anyway, where it is easier to read.
 *
 * Exactly the node's own rules and no others, so the client never rejects a
 * policy the node would accept. Both schemes are allowed: `https://` protects
 * the secret in transit, `http://` protects it by where the endpoint sits.
 */
function checkForwardURL(where: string, url: string): void {
  if (!/^https?:\/\//.test(url)) {
    throw new BurrowError(
      `${where}: a forward url must begin with http:// or https://`,
      "invalid_argument",
    );
  }
  if (url.includes("?") || url.includes("#")) {
    throw new BurrowError(
      `${where}: a forward url may not carry a query string or a fragment`,
      "invalid_argument",
    );
  }
}

function checkHeaderName(where: string, name: string): void {
  if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(name)) {
    throw new BurrowError(
      `${where}: ${JSON.stringify(name)} is not a valid header name`,
      "invalid_argument",
    );
  }
}

/** Reads one wire `RequestRule` back. Secrets arrive redacted. */
function fromRequestRule(raw: any): AppliedRule {
  const rule: AppliedRule = { domain: raw?.domain ?? "" };
  const match = fromRequestMatch(raw?.match);
  if (match) rule.match = match;
  const expiresAt = Number(raw?.expiresAtUnixMs ?? 0);
  if (expiresAt) rule.expiresAt = new Date(expiresAt);
  if (raw?.boundSandboxId) rule.boundSandboxId = raw.boundSandboxId;
  if (raw?.forward) {
    rule.forward = {
      url: raw.forward.url ?? "",
      secret: raw.forward.secret ?? "",
    };
  } else if (raw?.setHeaders) {
    rule.setHeaders = Object.fromEntries(
      (raw.setHeaders.headers ?? []).map((header: any) => [
        header.name ?? "",
        header.value ?? "",
      ]),
    );
  }
  return rule;
}

function fromRequestMatch(raw: any): RequestMatch | undefined {
  if (!raw) return undefined;
  const match: RequestMatch = {};
  if (raw.path) match.path = fromStringMatch(raw.path);
  if (raw.methods?.length) match.method = raw.methods;
  if (raw.query?.length) match.queryString = fromFieldMatches(raw.query);
  if (raw.headers?.length) match.headers = fromFieldMatches(raw.headers);
  return match;
}

function fromFieldMatches(raw: any[]): Record<string, StringMatch> {
  return Object.fromEntries(
    raw.map((field: any) => [field.key ?? "", fromStringMatch(field.value)]),
  );
}

function fromStringMatch(raw: any): StringMatch {
  const op = OP_FROM_WIRE[String(raw?.op ?? "")] ?? "exact";
  return { [op]: raw?.value ?? "" } as StringMatch;
}

const PROTOCOLS = ["tcp", "udp"] as const;
const PROTOCOL_PREFIX = "PORT_PROTOCOL_";

/** Everything burrow understands on a port rule. */
const PORT_RULE_KEYS = new Set(["protocol", "port", "portEnd", "cidrs"]);

/**
 * Builds one wire `PortRule`.
 *
 * Ranges and CIDRs are the node's to check. What is checked here is what would
 * otherwise be misread without a word: a misspelt protocol must not become
 * "both", and a misspelt `cidrs` must not turn a denial meant for one range
 * into one for every destination.
 */
function toPortRule(index: number, rule: PortRule): any {
  const where = `networkPolicy.denyPorts[${index}]`;
  for (const key of Object.keys(rule ?? {})) {
    if (PORT_RULE_KEYS.has(key)) continue;
    throw new BurrowError(
      `${where}: unknown key ${JSON.stringify(key)}; one of protocol, port, portEnd, cidrs`,
      "invalid_argument",
    );
  }
  if (rule.protocol !== undefined && !(PROTOCOLS as readonly string[]).includes(rule.protocol)) {
    throw new BurrowError(
      `${where}: unknown protocol ${JSON.stringify(rule.protocol)}; tcp, udp, or omitted for both`,
      "invalid_argument",
    );
  }
  if (!Number.isInteger(rule.port)) {
    throw new BurrowError(`${where}: port is an integer`, "invalid_argument");
  }
  return {
    protocol:
      rule.protocol === undefined
        ? "PORT_PROTOCOL_UNSPECIFIED"
        : enumTo(PROTOCOL_PREFIX, rule.protocol),
    port: rule.port,
    portEnd: rule.portEnd ?? 0,
    cidrs: rule.cidrs ?? [],
  };
}

/** Reads one wire `PortRule` back, leaving out what was left unset. */
function fromPortRule(raw: any): PortRule {
  const rule: PortRule = { port: Number(raw?.port ?? 0) };
  const protocol = enumOf(raw?.protocol, PROTOCOL_PREFIX, PROTOCOLS);
  if (protocol !== "unknown") rule.protocol = protocol;
  const portEnd = Number(raw?.portEnd ?? 0);
  if (portEnd) rule.portEnd = portEnd;
  if (raw?.cidrs?.length) rule.cidrs = raw.cidrs;
  return rule;
}

const INGRESS_PREFIX = "INGRESS_PROTOCOL_";
const INGRESS_PROTOCOLS = ["tcp", "udp", "icmp"] as const;
const INGRESS_KEYS = new Set(["protocol", "ports", "sources"]);

/** Builds one wire `IngressRule`, refusing what would otherwise be misread. */
function toIngressRule(index: number, rule: IngressRule): any {
  const where = `networkPolicy.ingress[${index}]`;
  for (const key of Object.keys(rule ?? {})) {
    if (INGRESS_KEYS.has(key)) continue;
    throw new BurrowError(
      `${where}: unknown key ${JSON.stringify(key)}; one of protocol, ports, sources`,
      "invalid_argument",
    );
  }
  if (
    rule.protocol !== undefined &&
    !(INGRESS_PROTOCOLS as readonly string[]).includes(rule.protocol)
  ) {
    throw new BurrowError(
      `${where}: unknown protocol ${JSON.stringify(rule.protocol)}; tcp, udp, icmp, or omitted for both`,
      "invalid_argument",
    );
  }
  const ports = (rule.ports ?? []).map((entry) => {
    const match = /^(\d+)(?:-(\d+))?$/.exec(String(entry));
    if (!match) {
      throw new BurrowError(
        `${where}: port ${JSON.stringify(entry)} is not N or N-M`,
        "invalid_argument",
      );
    }
    return { port: Number(match[1]), portEnd: match[2] ? Number(match[2]) : 0 };
  });
  return {
    protocol:
      rule.protocol === undefined
        ? "INGRESS_PROTOCOL_UNSPECIFIED"
        : enumTo(INGRESS_PREFIX, rule.protocol),
    ports,
    sources: rule.sources ?? [],
  };
}

/** Reads one wire `IngressRule` back, ports as numbers or `"N-M"` ranges. */
function fromIngressRule(raw: any): IngressRule {
  const rule: IngressRule = {};
  const protocol = enumOf(raw?.protocol, INGRESS_PREFIX, INGRESS_PROTOCOLS);
  if (protocol !== "unknown") rule.protocol = protocol;
  if (raw?.ports?.length) {
    rule.ports = raw.ports.map((range: any) =>
      Number(range?.portEnd ?? 0) ? `${range.port}-${range.portEnd}` : Number(range?.port ?? 0),
    );
  }
  if (raw?.sources?.length) rule.sources = raw.sources;
  return rule;
}

/** Builds the wire `NetworkPolicy`. Defaults to no egress at all. */
export function toNetworkPolicy(options: NetworkPolicyOptions = {}): any {
  const mode = options.mode ?? "none";
  // A mode with no wire name would otherwise go out as `undefined` and be
  // decoded as NETWORK_MODE_NONE, a typo costing the sandbox all its egress.
  if (!MODES.includes(mode)) {
    throw new BurrowError(
      `networkPolicy: unknown mode ${JSON.stringify(mode)}; one of none, allowlist, open`,
      "invalid_argument",
    );
  }
  const rules = options.rules ?? [];
  // Rules apply only to requests the proxy inspects. In allowlist mode it
  // inspects only traffic to allowed domains: with none, every rule would be
  // dropped without a word. Open mode inspects the hosts the rules name.
  if (rules.length > 0 && mode !== "open" && !options.allowDomains?.length) {
    throw new BurrowError(
      "networkPolicy: rules apply only to inspected requests, so their domains have to be in allowDomains",
      "invalid_argument",
    );
  }
  return {
    mode: enumTo(MODE_PREFIX, mode),
    allowDomains: options.allowDomains ?? [],
    allowCidrs: options.allowCidrs ?? [],
    allowPorts: options.allowPorts ?? [],
    denyCidrs: options.denyCidrs ?? [],
    denyDomains: options.denyDomains ?? [],
    denyPorts: (options.denyPorts ?? []).map((rule, index) => toPortRule(index, rule)),
    isIpv6Denied: options.denyIpv6 ?? false,
    ingress: (options.ingress ?? []).map((rule, index) => toIngressRule(index, rule)),
    isTlsInspected: options.inspectTls ?? false,
    rules: rules.map(toRequestRule),
  };
}

/** Reads a `NetworkPolicy` back. Secrets arrive redacted. */
export function fromNetworkPolicy(raw: any): NetworkPolicy {
  const mode = enumOf(raw?.mode, MODE_PREFIX, MODES);
  return {
    mode: mode === "unknown" ? "none" : mode,
    allowDomains: raw?.allowDomains ?? [],
    allowCidrs: raw?.allowCidrs ?? [],
    allowPorts: (raw?.allowPorts ?? []).map(Number),
    denyCidrs: raw?.denyCidrs ?? [],
    denyDomains: raw?.denyDomains ?? [],
    denyPorts: (raw?.denyPorts ?? []).map(fromPortRule),
    denyIpv6: Boolean(raw?.isIpv6Denied),
    ingress: (raw?.ingress ?? []).map(fromIngressRule),
    inspectTls: Boolean(raw?.isTlsInspected),
    rules: (raw?.rules ?? []).map(fromRequestRule),
  };
}

/** Builds the wire `ResourcePolicy`. Zero means "server default" throughout. */
export function toResourcePolicy(options: ResourceOptions = {}): any {
  return {
    // Zero rather than 1 and 512: sending the defaults as if the caller had
    // asked makes a create from a snapshot look like a shape change.
    vcpus: options.vcpus ?? 0,
    memMib: options.memoryMib ?? 0,
    diskMib: options.diskMib ?? 0,
    cpus: options.cpus ?? 0,
    cpuShares: options.cpuShares ?? 0,
    cpusetCpus: options.cpusetCpus ?? "",
    blkioWeight: options.blkioWeight ?? 0,
  };
}

export function fromResourcePolicy(raw: any): ResourcePolicy {
  return {
    vcpus: Number(raw?.vcpus ?? 0),
    memoryMib: Number(raw?.memMib ?? 0),
    diskMib: Number(raw?.diskMib ?? 0),
    cpus: Number(raw?.cpus ?? 0),
    cpuShares: Number(raw?.cpuShares ?? 0),
    cpusetCpus: raw?.cpusetCpus ?? "",
    blkioWeight: Number(raw?.blkioWeight ?? 0),
  };
}

export function toLifetimePolicy(options: LifetimeOptions = {}): any {
  return {
    maxLifetimeSecs: options.maxLifetimeSecs ?? 0,
    idleSuspendSecs: options.idleSuspendSecs ?? 0,
    suspendedTtlSecs: options.suspendedTtlSecs ?? 0,
    checkpointSecs: options.checkpointSecs ?? 0,
    isMemoryCheckpointed: options.checkpointMemory ?? false,
  };
}

export function fromLifetimePolicy(raw: any): LifetimePolicy {
  return {
    maxLifetimeSecs: Number(raw?.maxLifetimeSecs ?? 0),
    idleSuspendSecs: Number(raw?.idleSuspendSecs ?? 0),
    suspendedTtlSecs: Number(raw?.suspendedTtlSecs ?? 0),
    checkpointSecs: Number(raw?.checkpointSecs ?? 0),
    checkpointMemory: Boolean(raw?.isMemoryCheckpointed),
  };
}

export function toSnapshotPolicy(options: SnapshotPolicyOptions = {}): any {
  return {
    expirationSecs: options.expirationSecs ?? 0,
    keepLast: options.keepLast ?? 0,
    isEvictedKept: options.keepEvicted ?? false,
  };
}

export function fromSnapshotPolicy(raw: any): SnapshotPolicy {
  return {
    expirationSecs: Number(raw?.expirationSecs ?? 0),
    keepLast: Number(raw?.keepLast ?? 0),
    keepEvicted: Boolean(raw?.isEvictedKept),
  };
}

/**
 * Normalises private-network memberships.
 *
 * A bare string is the common case: join the network, talk both ways, answer
 * to the sandbox id. The object form is there for the rest.
 */
export function toNetworks(
  networks: ReadonlyArray<string | NetworkMembership> | undefined,
  alias?: string,
): any[] {
  return (networks ?? []).map((entry) => {
    const membership: NetworkMembership =
      typeof entry === "string" ? { network: entry } : entry;
    return {
      network: membership.network,
      ingressPorts: membership.ingressPorts ?? [],
      isEgressAllowed: membership.allowEgress ?? true,
      isIngressAllowed: membership.allowIngress ?? true,
      alias: membership.alias ?? alias ?? "",
    };
  });
}

export function fromNetworks(raw: any): Required<NetworkMembership>[] {
  return (raw ?? []).map((entry: any) => ({
    network: entry.network ?? "",
    ingressPorts: (entry.ingressPorts ?? []).map(Number),
    allowEgress: Boolean(entry.isEgressAllowed),
    allowIngress: Boolean(entry.isIngressAllowed),
    alias: entry.alias ?? "",
  }));
}

/**
 * Builds the wire `ExecPolicy`, or nothing at all.
 *
 * An absent section means "allowed" to the node, so options that restrict
 * nothing send no section rather than a permissive one.
 */
export function toExecPolicy(options: ExecOptions | undefined): any {
  if (!options) return undefined;
  return { isExecAllowed: options.allowExec ?? true };
}

/** Builds the wire `FsPolicy`, or nothing at all. */
export function toFsPolicy(options: FsOptions | undefined): any {
  if (!options) return undefined;
  return {
    isUploadAllowed: options.allowUpload ?? true,
    isDownloadAllowed: options.allowDownload ?? true,
    pathScopes: options.pathScopes ?? [],
    maxUploadBytes: options.maxUploadBytes ?? 0,
  };
}

export function fromExecPolicy(raw: any): ExecPolicy | undefined {
  if (!raw) return undefined;
  return { allowExec: Boolean(raw.isExecAllowed) };
}

export function fromFsPolicy(raw: any): FsPolicy | undefined {
  if (!raw) return undefined;
  return {
    allowUpload: Boolean(raw.isUploadAllowed),
    allowDownload: Boolean(raw.isDownloadAllowed),
    pathScopes: raw.pathScopes ?? [],
    maxUploadBytes: Number(raw.maxUploadBytes ?? 0),
  };
}

export function toVolumeMounts(mounts: ReadonlyArray<VolumeMount> | undefined): any[] {
  return (mounts ?? []).map((mount) => ({
    volume: mount.volume,
    path: mount.path,
    isReadOnly: mount.readOnly ?? false,
  }));
}

export function fromVolumeMounts(raw: any): Required<VolumeMount>[] {
  return (raw ?? []).map((mount: any) => ({
    volume: String(mount?.volume ?? ""),
    path: String(mount?.path ?? ""),
    readOnly: Boolean(mount?.isReadOnly),
    generation: Number(mount?.generation ?? 0),
  }));
}

/** Builds a `KitSpec`. Absent inputs are sent empty, which the node reads as none. */
export function toKitSpec(kit: KitOptions | undefined): any {
  return {
    args: kit?.args ?? {},
    env: kit?.env ?? {},
    rejectTypes: [...(kit?.rejectCapabilities ?? [])],
  };
}

export function fromPolicy(raw: any): SandboxPolicy {
  return {
    resources: fromResourcePolicy(raw?.resources),
    lifetime: fromLifetimePolicy(raw?.lifetime),
    snapshots: fromSnapshotPolicy(raw?.snapshots),
    exec: fromExecPolicy(raw?.exec),
    fs: fromFsPolicy(raw?.fs),
    network: fromNetworkPolicy(raw?.network),
    networks: fromNetworks(raw?.networks),
    volumes: fromVolumeMounts(raw?.volumes),
  };
}
