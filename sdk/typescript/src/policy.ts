/**
 * Policy conversion between the SDK's flat options and the wire shape
 * `burrow.common.v1.Policy`, so nothing else assembles proto objects inline.
 */

import { BurrowError } from "./errors.js";
import type {
  ExecOptions,
  ExecPolicy,
  FsOptions,
  FsPolicy,
  HeaderInjection,
  NetworkInput,
  NetworkMembership,
  NetworkMode,
  NetworkPolicy,
  NetworkPolicyOptions,
  RequestMatch,
  RequestRule,
  ResourceOptions,
  ResourcePolicy,
  SandboxPolicy,
  StringMatch,
} from "./types.js";

const MODE_TO_WIRE: Record<NetworkMode, string> = {
  none: "NETWORK_MODE_NONE",
  allowlist: "NETWORK_MODE_ALLOWLIST",
  open: "NETWORK_MODE_OPEN",
};

const MODE_FROM_WIRE: Record<string, NetworkMode> = {
  NETWORK_MODE_NONE: "none",
  NETWORK_MODE_ALLOWLIST: "allowlist",
  NETWORK_MODE_OPEN: "open",
};

/** A bare mode stands for a policy with only that mode set. */
export function resolveNetwork(network: NetworkInput | undefined): NetworkPolicyOptions {
  if (typeof network === "string") return { mode: network };
  return network ?? {};
}

/** Everything burrow understands on a rule. */
const RULE_KEYS = new Set(["domain", "match", "setHeaders", "forward"]);

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

const OP_TO_WIRE: Record<string, string> = {
  exact: "STRING_MATCH_OP_EXACT",
  startsWith: "STRING_MATCH_OP_STARTS_WITH",
  regex: "STRING_MATCH_OP_REGEX",
};

const OP_FROM_WIRE: Record<string, "exact" | "startsWith" | "regex"> = {
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
    throw new BurrowError(
      `${where}: a match pattern is a string`,
      "invalid_argument",
    );
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
    methods:
      method === undefined ? [] : Array.isArray(method) ? method : [method],
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
  const wire: any = {
    domain: rule.domain,
    match: toRequestMatch(where, rule.match),
  };
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
function fromRequestRule(raw: any): RequestRule {
  const rule: RequestRule = { domain: raw?.domain ?? "" };
  const match = fromRequestMatch(raw?.match);
  if (match) rule.match = match;
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

/** Builds the wire `NetworkPolicy`. Defaults to no egress at all. */
export function toNetworkPolicy(options: NetworkPolicyOptions = {}): any {
  const mode = options.mode ?? "none";
  // A mode with no wire name would otherwise go out as `undefined` and be
  // decoded as NETWORK_MODE_NONE, a typo costing the sandbox all its egress.
  if (!(mode in MODE_TO_WIRE)) {
    throw new BurrowError(
      `networkPolicy: unknown mode ${JSON.stringify(mode)}; one of none, allowlist, open`,
      "invalid_argument",
    );
  }
  // Rules first, then the injections: an injection carries no matcher, so it
  // claims every request to its domain and would shadow anything after it.
  const rules = [
    ...(options.rules ?? []),
    ...(options.injectHeaders ?? []).map(
      (header): RequestRule => ({
        domain: header.domain,
        setHeaders: { [header.name]: header.value },
      }),
    ),
  ];
  // Rules apply only to requests the proxy inspects, and it inspects only
  // traffic to allowed domains: with none, every rule would be dropped
  // without a word.
  if (rules.length > 0 && !options.allowDomains?.length) {
    throw new BurrowError(
      "networkPolicy: rules apply only to inspected requests, so their domains have to be in allowDomains",
      "invalid_argument",
    );
  }
  return {
    mode: MODE_TO_WIRE[mode],
    allowDomains: options.allowDomains ?? [],
    allowCidrs: options.allowCidrs ?? [],
    allowPorts: options.allowPorts ?? [],
    denyCidrs: options.denyCidrs ?? [],
    isTlsInspected: options.inspectTls ?? false,
    rules: rules.map(toRequestRule),
  };
}

/** Reads a `NetworkPolicy` back. Secrets arrive redacted. */
export function fromNetworkPolicy(raw: any): NetworkPolicy {
  const rules: RequestRule[] = (raw?.rules ?? []).map(fromRequestRule);
  return {
    mode: MODE_FROM_WIRE[String(raw?.mode ?? "")] ?? "none",
    allowDomains: raw?.allowDomains ?? [],
    allowCidrs: raw?.allowCidrs ?? [],
    allowPorts: (raw?.allowPorts ?? []).map(Number),
    denyCidrs: raw?.denyCidrs ?? [],
    inspectTls: Boolean(raw?.isTlsInspected),
    rules,
    // The rules that are exactly what `injectHeaders` used to describe, so
    // code written before rules existed still reads what it wrote.
    injectHeaders: rules.flatMap((rule): HeaderInjection[] =>
      rule.match || !rule.setHeaders
        ? []
        : Object.entries(rule.setHeaders).map(([name, value]) => ({
            domain: rule.domain,
            name,
            value,
          })),
    ),
  };
}

/** Builds the wire `ResourcePolicy`. Zero means "server default" throughout. */
export function toResourcePolicy(options: ResourceOptions = {}): any {
  return {
    // Zero rather than 1 and 512: sending the defaults as if the caller had
    // asked makes a create from a snapshot look like a shape change.
    vcpus: options.vcpus ?? 0,
    memMib: options.memoryMib ?? 0,
    scratchDiskMib: options.diskMib ?? 0,
    maxLifetimeSecs: options.maxLifetimeSecs ?? 0,
    idleSuspendSecs: options.idleSuspendSecs ?? 0,
    suspendedTtlSecs: options.suspendedTtlSecs ?? 0,
    snapshotExpirationSecs: options.snapshotExpirationSecs ?? 0,
    keepLastSnapshots: options.keepLastSnapshots ?? 0,
    isEvictedSnapshotKept: options.keepEvictedSnapshots ?? false,
  };
}

export function fromResourcePolicy(raw: any): ResourcePolicy {
  return {
    vcpus: Number(raw?.vcpus ?? 0),
    memoryMib: Number(raw?.memMib ?? 0),
    diskMib: Number(raw?.scratchDiskMib ?? 0),
    maxLifetimeSecs: Number(raw?.maxLifetimeSecs ?? 0),
    idleSuspendSecs: Number(raw?.idleSuspendSecs ?? 0),
    suspendedTtlSecs: Number(raw?.suspendedTtlSecs ?? 0),
    snapshotExpirationSecs: Number(raw?.snapshotExpirationSecs ?? 0),
    keepLastSnapshots: Number(raw?.keepLastSnapshots ?? 0),
    keepEvictedSnapshots: Boolean(raw?.isEvictedSnapshotKept ?? false),
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

export function fromNetworks(raw: any): NetworkMembership[] {
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

export function toVolumeMounts(
  mounts: ReadonlyArray<import("./types.js").VolumeMount> | undefined,
): any[] {
  return (mounts ?? []).map((mount) => ({
    volume: mount.volume,
    path: mount.path,
    isReadOnly: mount.readOnly ?? false,
  }));
}

export function fromVolumeMounts(raw: any): import("./types.js").VolumeMount[] {
  return (raw ?? []).map((mount: any) => ({
    volume: String(mount?.volume ?? ""),
    path: String(mount?.path ?? ""),
    readOnly: Boolean(mount?.isReadOnly),
  }));
}

export function fromPolicy(raw: any): SandboxPolicy {
  return {
    resources: fromResourcePolicy(raw?.resources),
    exec: fromExecPolicy(raw?.exec),
    fs: fromFsPolicy(raw?.fs),
    network: fromNetworkPolicy(raw?.network),
    networks: fromNetworks(raw?.networks),
    volumes: fromVolumeMounts(raw?.volumes),
  };
}
