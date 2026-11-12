// Type-only, so it is erased rather than becoming an import cycle.
import type { Sandbox } from "./sandbox.js";

/** Egress policy for a sandbox. */
export type NetworkMode = "none" | "allowlist" | "open";

export type SandboxState =
  | "creating"
  | "running"
  | "suspended"
  | "stopped"
  | "destroyed"
  | "failed"
  | "unknown";

/** Options accepted by every call, alongside whatever else it takes. */
export interface CallOptions {
  /** Cancels the call. An aborted call rejects with code `"cancelled"`. */
  signal?: AbortSignal;
  /** Deadline for this call, over the client's default. */
  timeoutMs?: number;
}

/**
 * How one string is compared. A bare string is an exact match.
 *
 * The node's regex engine does not backtrack, so no pattern costs unbounded
 * work. A pattern is at most 256 bytes, and one that does not compile is
 * refused when the policy is set rather than when a request would have used it.
 */
export type StringMatch =
  | string
  | { exact: string }
  | { startsWith: string }
  | { regex: string };

/**
 * Which requests a rule applies to.
 *
 * A matcher never blocks: a request matching nothing is still allowed, just
 * unmodified. Every dimension given must match; one left out is not examined.
 * Paths, methods and header *values* are compared case-sensitively, header
 * names are not. At most eight methods, query entries and header entries each.
 */
export interface RequestMatch {
  /** Compared against the path alone, without the query string. */
  path?: StringMatch;
  /** Any one matching is enough. */
  method?: string | string[];
  /** All must match. A repeated key matches if any of its values does. */
  queryString?: Record<string, StringMatch>;
  /** All must match, on the same any-value rule. */
  headers?: Record<string, StringMatch>;
}

/** Sending a request to an endpoint you control instead of to the origin. */
export interface ForwardRequest {
  /**
   * An `http://` or `https://` endpoint, with no query string and no fragment.
   * An `https://` endpoint's certificate is verified against the public roots,
   * which cannot be turned off.
   */
  url: string;
  /**
   * Shared secret sent as `burrow-forwarded-secret`. It proves the request
   * came from a node holding the secret and nothing more. `https://` keeps it
   * off the wire in the clear; with `http://` the endpoint has to be reachable
   * only by the node. Redacted on every read.
   */
  secret?: string;
}

/**
 * One rule the host applies to inspected requests for a domain.
 *
 * Rules are evaluated in order and the first whose domain and matcher both
 * match wins, so a rule with no `match` shadows every rule after it for that
 * domain.
 */
export interface RequestRule {
  /**
   * Domain glob, matched exactly like `allowDomains`. In open mode an exact
   * host name, since it also names the one host whose TLS is inspected.
   */
  domain: string;
  match?: RequestMatch;
  /** Headers set on the request, replacing whatever the guest sent. */
  setHeaders?: Record<string, string>;
  forward?: ForwardRequest;
  /**
   * When the rule stops applying, with no further call. Omitted never
   * expires.
   */
  expiresAt?: Date;
}

/** A rule as the server reports it. Secrets arrive redacted. */
export interface AppliedRule extends RequestRule {
  /**
   * The one sandbox the rule applies in, set by the server on a rule whose
   * value came from a scoped secret. A copy of the policy elsewhere, a fork
   * for instance, refuses the requests the rule would have claimed.
   */
  boundSandboxId?: string;
}

/** Who may use a secret. Both empty, the default, is every sandbox. */
export interface SecretScope {
  /** Sandbox ids or names. */
  sandboxes?: string[];
  /** Tags as `key=value`. */
  tags?: string[];
}

/** A stored secret's name and scope. The value is never returned. */
export interface SecretInfo {
  name: string;
  scope: SecretScope;
}

/**
 * Destination ports a sandbox may never connect to, optionally narrowed to
 * destination ranges.
 */
export interface PortRule {
  /** Omitted is both TCP and UDP. */
  protocol?: "tcp" | "udp";
  /** First port, 1 to 65535. */
  port: number;
  /** Inclusive end of a range. Omitted or 0 is `port` alone. */
  portEnd?: number;
  /**
   * IPv4 or IPv6 CIDRs the denial is limited to. Omitted or empty is every
   * destination. At most 16.
   */
  cidrs?: string[];
}

/**
 * One door into a sandbox's public addresses, IPv4 and IPv6. Nothing is
 * admitted without a rule.
 */
export interface IngressRule {
  /** Omitted is both TCP and UDP. `icmp` admits echo and takes no ports. */
  protocol?: "tcp" | "udp" | "icmp";
  /** Ports and ranges, e.g. `[25, 587]` or `["27000-27015"]`. Omitted is every port. */
  ports?: (number | string)[];
  /** Source CIDRs of either family. Omitted is anyone. */
  sources?: string[];
}

/** Egress policy in full. A bare mode, `networkPolicy: "open"`, sets only `mode`. */
export interface NetworkPolicyOptions {
  /** Defaults to `"none"`: no egress at all. */
  mode?: NetworkMode;
  /**
   * Domains reachable in `"allowlist"` mode, e.g. `["pypi.org",
   * "*.pythonhosted.org"]`. A leading `*.` matches subdomains but not the
   * apex.
   */
  allowDomains?: string[];
  /** Extra destinations permitted at the IP layer, e.g. `["10.0.0.0/8"]`. */
  allowCidrs?: string[];
  /** Destination ports permitted. Empty means the mode's defaults. */
  allowPorts?: number[];
  /**
   * Ranges this sandbox may never reach, in any mode. Deny beats every
   * allowance: an allowed domain that resolves into one of these is refused.
   */
  denyCidrs?: string[];
  /** Domain globs refused in every mode, before any allowance is consulted. */
  denyDomains?: string[];
  /**
   * Destination ports this sandbox may never connect to, in every mode,
   * ahead of every allowance, e.g. `[{ protocol: "tcp", port: 25 }]`. At
   * most 64.
   */
  denyPorts?: PortRule[];
  /**
   * Refuse every IPv6 destination, in every mode. Off by default, which keeps
   * each mode's own IPv6 behaviour.
   */
  denyIpv6?: boolean;
  /**
   * What may reach the sandbox's public addresses from outside. Default deny;
   * replies to connections the sandbox opened are always admitted. At most 64.
   */
  ingress?: IngressRule[];
  /**
   * Terminate the sandbox's TLS so the host named inside the session is
   * checked too, not just the SNI. Required by `rules`.
   */
  inspectTls?: boolean;
  /**
   * What the host does to the requests it inspects, in order. Requires
   * `inspectTls`. At most 32.
   */
  rules?: RequestRule[];
}

/** Every accepted spelling of an egress policy. */
export type NetworkInput = NetworkMode | NetworkPolicyOptions;

/** Egress policy as the server reports it. Injected values arrive redacted. */
export type NetworkPolicy = Required<Omit<NetworkPolicyOptions, "rules">> & {
  /** What the host does to inspected requests, in order. Secrets are redacted. */
  rules: AppliedRule[];
};

/** Machine shape. Every `0` means "the server's default". */
export interface ResourceOptions {
  vcpus?: number;
  memoryMib?: number;
  /** Root disk, at least the template's image. 0 is the image plus 1024. */
  diskMib?: number;
}

export type ResourcePolicy = Required<ResourceOptions>;

/** How long the sandbox stays paid for. Every `0` means "unlimited". */
export interface LifetimeOptions {
  /** Hard cap on how long the sandbox may live. 0 is unlimited. */
  maxLifetimeSecs?: number;
  /** Suspend after this many idle seconds. 0 never suspends. */
  idleSuspendSecs?: number;
  /**
   * Delete a sandbox that has been suspended this long, releasing its disk and
   * its address lease. 0 keeps it forever. Measured from the moment it entered
   * `suspended`, so it composes with `idleSuspendSecs`.
   */
  suspendedTtlSecs?: number;
  /**
   * Checkpoint the running sandbox into the object store this often, so a
   * node that dies takes only what changed since. Raised to the node's floor
   * (`burrowd --checkpoint-min-secs`). 0 never checkpoints. Needs an object
   * store.
   */
  checkpointSecs?: number;
  /**
   * Capture memory in each checkpoint as well, so a recovery resumes the
   * guest's processes rather than booting on its disk. Pauses the guest for
   * the memory write.
   */
  checkpointMemory?: boolean;
}

export type LifetimePolicy = Required<LifetimeOptions>;

/** What a checkpoint holds: the disks, or memory too. */
export type CheckpointKind = "disk" | "memory";

/** How long snapshots taken of the sandbox stay paid for. */
export interface SnapshotPolicyOptions {
  /**
   * Sweep snapshots of this sandbox this many seconds after they were last
   * used, where a use is a sandbox created from one. 0 keeps them until
   * something deletes them.
   */
  expirationSecs?: number;
  /**
   * Keep only this many snapshots of the sandbox, evicting the oldest as a new
   * one is taken. 1 to 10; 0 is unlimited.
   */
  keepLast?: number;
  /**
   * Let a snapshot that `keepLast` evicts live out its expiration instead of
   * being deleted at once. Needs both `keepLast` and `expirationSecs`;
   * without an expiry the server refuses it, since nothing would ever reclaim
   * what was kept.
   */
  keepEvicted?: boolean;
}

export type SnapshotPolicy = Required<SnapshotPolicyOptions>;

/** One volume attached to one sandbox at one path. */
export interface VolumeMount {
  /** Name of an existing volume. */
  volume: string;
  /**
   * Absolute path in the guest. Mount paths may not overlap each other, and
   * may not sit inside `/proc`, `/sys`, `/dev`, `/tmp`, `/run`, `/etc`, `/usr`
   * or `/bin`.
   */
  path: string;
  /**
   * Read-only mounts of one volume can be held by any number of sandboxes at
   * once. A writable mount, the default, is exclusive to one running sandbox.
   */
  readOnly?: boolean;
  /**
   * Read back only. For a read-only mount of a durable volume another node
   * holds: the uploaded generation this sandbox reads a copy of, as Unix
   * milliseconds of that upload. It sees the volume as of then, and newer data
   * only on its next mount. 0 on the node holding the volume.
   */
  generation?: number;
}

/** Membership in a named private inter-sandbox network. */
export interface NetworkMembership {
  network: string;
  /** Ports this member accepts from peers. Empty means all of them. */
  ingressPorts?: number[];
  allowEgress?: boolean;
  allowIngress?: boolean;
  /**
   * Name this sandbox answers to, as `<alias>.<network>.internal`. Defaults to
   * the sandbox id, which always resolves.
   */
  alias?: string;
}

/**
 * Whether callers may run commands in the sandbox.
 *
 * Enforced on the node, before an exec reaches the guest. A sandbox created
 * without this option allows exec.
 */
export interface ExecOptions {
  /** Defaults to true. `false` refuses commands, terminals and signals. */
  allowExec?: boolean;
}

/**
 * What callers may do to the sandbox's filesystem.
 *
 * Enforced on the node, before a path or a byte reaches the guest. A sandbox
 * created without this option allows everything.
 */
export interface FsOptions {
  /** Defaults to true. */
  allowUpload?: boolean;
  /** Defaults to true. */
  allowDownload?: boolean;
  /**
   * Absolute paths uploads, downloads and listings are confined to, matched on
   * whole components so `/data` does not admit `/database`. At most 16; empty
   * is the whole filesystem.
   */
  pathScopes?: string[];
  /** Ceiling on a single upload, in bytes. 0 is unlimited. */
  maxUploadBytes?: number;
}

export type ExecPolicy = Required<ExecOptions>;

export type FsPolicy = Required<FsOptions>;

export interface SandboxPolicy {
  resources: ResourcePolicy;
  lifetime: LifetimePolicy;
  snapshots: SnapshotPolicy;
  /** Absent when the sandbox places no limit on exec. */
  exec?: ExecPolicy;
  /** Absent when the sandbox places no limit on file access. */
  fs?: FsPolicy;
  network: NetworkPolicy;
  networks: Required<NetworkMembership>[];
  /** Volumes the sandbox has mounted. */
  volumes: Required<VolumeMount>[];
}

/**
 * What a sandbox has actually consumed.
 *
 * Accumulated across every VM it has run, so a pause and a resume do not
 * reset it. A sandbox that has not run anything reports zeroes.
 */
export interface Usage {
  /**
   * Host CPU in microseconds, read from the sandbox's cgroup. That covers the
   * whole VMM: the guest's vCPU threads and the hypervisor's own work for them.
   */
  cpuUsageUsec: number;
  /** Bytes delivered to the guest, counted at its tap. */
  rxBytes: number;
  /** Bytes the guest sent, counted at the same place. */
  txBytes: number;
}

/** The machine {@link Sandbox.updateResources} changes. */
export interface ResourceUpdateOptions extends CallOptions {
  vcpus?: number;
  memoryMib?: number;
  diskMib?: number;
}

/**
 * What became of one field. `live`: applied to the running guest.
 * `next_boot`: recorded on a shut-down sandbox for its next boot. `offline`:
 * a shut-down sandbox's disk resized now. `refused`: not applied, and
 * `reason` says why. `unchanged`: it already had that value.
 */
export type ResourceChange = "unchanged" | "live" | "next_boot" | "offline" | "refused" | "unknown";

/** What became of one field of {@link Sandbox.updateResources}. */
export interface ResourceOutcome {
  change: ResourceChange;
  previous: number;
  /** What the sandbox has now: the value asked for, or `previous` when refused. */
  value: number;
  reason: string;
}

/** What {@link Sandbox.updateResources} did, a field per one asked for. */
export interface ResourcesUpdate {
  vcpus?: ResourceOutcome;
  memoryMib?: ResourceOutcome;
  diskMib?: ResourceOutcome;
  /**
   * The root filesystem's size after a disk change, in bytes. 0 when no guest
   * has seen the disk yet: a shut-down sandbox grown, whose guest fills it on
   * its next boot.
   */
  filesystemBytes: number;
}

/**
 * One VM boot inside a sandbox's life.
 *
 * A sandbox outlives its VMs: a pause ends one and a resume starts the next,
 * and a fork or a create from a snapshot starts one from state written
 * elsewhere.
 */
export interface Session {
  id: string;
  sandboxId: string;
  startedAt: Date;
  /**
   * `null` while the session is open, and for one the node died during:
   * nothing recorded when that VM stopped.
   */
  endedAt: Date | null;
  startedBy: SessionStart;
  /** `null` while the session is open. */
  endedBy: SessionEnd | null;
}

/**
 * How a VM started. `boot` is from a template, `restore` from a fork or a
 * snapshot, `resume` from the sandbox's own suspend state.
 */
export type SessionStart = "boot" | "restore" | "resume" | "unknown";

/** How a VM stopped. `unknown` is a session that was open when the node died. */
export type SessionEnd = "suspended" | "deleted" | "failed" | "stopped" | "unknown";

export interface SandboxInfo {
  id: string;
  /** The name it was created with, or `""` when it was created without one. */
  name: string;
  nodeId: string;
  template: string;
  state: SandboxState;
  createdAt: Date;
  /** Address the sandbox holds on the networks it joined. */
  guestIp: string;
  tags: Record<string, string>;
  policy: SandboxPolicy;
  /**
   * Whether the node hosting the sandbox has missed its heartbeats. When true,
   * `state` is a stale reading and calls fail until the node returns.
   */
  unreachable: boolean;
  /** What the sandbox has consumed, as of this reading. */
  usage: Usage;
  /**
   * Suspended with its latest suspend in the object store, so it can resume
   * on another node. A durable sandbox with an empty `nodeId` is held by no
   * node, and its next resume places it.
   */
  durable: boolean;
  /** The hypervisor it runs under, and the version its saved state needs. */
  hypervisor: string;
  hypervisorVersion: string;
  /** `linux`, `windows` or `macos`, from its template. */
  guestOs: string;
  /** Public addresses of either family attached to it. */
  publicIps: PublicIp[];
  /**
   * When its latest checkpoint was captured; `null` for none. Once its node
   * is gone, what it did after this is lost.
   */
  checkpointAt: Date | null;
  /**
   * What that checkpoint holds, and so what a recovery does: boot on the
   * saved disk, or resume the saved memory. `null` for none.
   */
  checkpointKind: CheckpointKind | null;
}

/** A dedicated public address, as the orchestrator records it. */
export interface PublicIp {
  address: string;
  /** 4 or 6. */
  family: number;
  /** The prefix routed to the sandbox: 32, or 128 or a subnet for IPv6. */
  prefixLen: number;
  pool: string;
  /** `allocated`, or `quarantined` while a released address sits out. */
  state: "allocated" | "quarantined" | "unknown";
  /** `""` while detached. */
  sandboxId: string;
  /** The node it reaches. A sandbox holding it stays there. */
  nodeId: string;
  allocatedAt: Date;
  /** `null` while detached. */
  attachedAt: Date | null;
  /** Set while a released address sits out its quarantine. */
  quarantinedUntil: Date | null;
}

/** Where public addresses come from. Operator configuration. */
export interface IpPool {
  name: string;
  /** One node, or every node carrying all of `nodeLabels`. */
  nodeId?: string;
  nodeLabels?: Record<string, string>;
  /** IPv4 ranges as `"first-last"`, and single addresses. */
  ranges?: string[];
  addresses?: string[];
  gateway?: string;
  /** The prefix of the gateway's network, e.g. 24. */
  prefixLen?: number;
  nameservers?: string[];
  /** An IPv6 prefix, and the size each sandbox gets from it. */
  prefix6?: string;
  perSandbox?: number;
  /** The upstream looks addresses up on the uplink, so the node answers for them. */
  onLink?: boolean;
  allowSmtp?: boolean;
  wakeOnTraffic?: boolean;
  quarantineSecs?: number;
  /** Read only. */
  total?: number;
  allocated?: number;
}

/** Options for {@link Ips.allocate}. */
export interface AllocateIpOptions extends CallOptions {
  pool?: string;
  /** 4 (the default) or 6. */
  family?: 4 | 6;
  /** Take one reaching this sandbox's node and attach it there, by id or name. */
  sandboxId?: string;
}

/** Options for {@link Ips.list}. */
export interface ListIpsOptions extends CallOptions {
  pool?: string;
  /** Only those attached to this sandbox, by id or name. */
  sandboxId?: string;
  /** Quarantined addresses too. Operators only. */
  quarantined?: boolean;
}

/** Inputs for a template pulled from a Sandbox Kit. */
export interface KitOptions {
  /** Create-phase arg values by name, applied to every Kit declaring the arg. */
  args?: Record<string, string>;
  /** Environment overrides for the Kit's processes, applied after image defaults. */
  env?: Record<string, string>;
  /**
   * Capability types to decline, by full name. A Kit requiring one is refused;
   * one asking optionally does without.
   */
  rejectCapabilities?: string[];
}

/** Options for {@link Sandbox.recreate}. */
export interface RecreateOptions extends CallOptions {
  /** Template for the new root disk. Omitted keeps the current one. */
  template?: string;
  /**
   * Kit inputs replacing the recorded ones: `args` and `env` by name,
   * `rejectCapabilities` wholesale, so an empty list clears it.
   */
  kit?: KitOptions;
}

/** What a handle keeps for itself, beside what the server holds. */
export interface HandleOptions {
  /**
   * Environment for every command this handle runs, under whatever a single
   * command passes.
   *
   * Held by the handle, not by the sandbox: there is nowhere on the server to
   * put it, so a handle obtained in another process does not have it. Bake
   * anything that has to survive into the template.
   */
  env?: Record<string, string>;
  /**
   * Resume a suspended sandbox and retry once when a call needs it running.
   * Defaults to true.
   */
  autoResume?: boolean;
  /** Called with the sandbox whenever this handle resumes it. */
  onResume?: (sandbox: Sandbox) => void | Promise<void>;
}

export interface CreateOptions extends CallOptions, HandleOptions {
  /**
   * Name for the sandbox, usable anywhere its id is, and the only identity a
   * caller chooses: ids are generated by the server. 1 to 63 characters of
   * lowercase letters, digits and `-`, not starting or ending with `-`.
   *
   * Unique across the fleet, so a name already in use fails with
   * `already_exists`, and fixed once the sandbox exists.
   */
  name?: string;
  /** Guest image to boot. */
  template?: string;
  /**
   * Snapshot id to start from. The sandbox **restores** that state instead of
   * booting, so it arrives with the snapshot's processes and memory, and
   * `template` and `resources` may not disagree with what the snapshot
   * holds. Placed on the node holding it: snapshots do not travel.
   */
  snapshot?: string;
  /** Machine shape. */
  resources?: ResourceOptions;
  /** The clocks the sandbox is measured against. */
  lifetime?: LifetimeOptions;
  /** Retention of the snapshots taken of it. */
  snapshots?: SnapshotPolicyOptions;
  /**
   * Egress policy. Defaults to `"none"`: a sandbox with no network at all.
   * Network access is opt-in, not opt-out. Pass a mode for the common case, or
   * an object for the full policy.
   */
  networkPolicy?: NetworkInput;
  /**
   * Private networks to join. Sandboxes sharing a network name can address
   * each other regardless of their egress policy: a member is reachable at
   * `<alias>.<network>.internal`, and at `<sandboxId>.<network>.internal`
   * whether or not an alias was set.
   */
  networks?: ReadonlyArray<string | NetworkMembership>;
  /**
   * Volumes to mount. A sandbox that mounts one is placed on the node holding
   * it, and boots cold rather than restoring a warm snapshot.
   */
  volumes?: ReadonlyArray<VolumeMount>;
  /**
   * Inputs for a template pulled from a Sandbox Kit. A Kit template is
   * provisioned the way its descriptors ask whether or not this is set; on
   * any other template it is ignored.
   */
  kit?: KitOptions;
  /**
   * Name this sandbox answers to on the networks it joins. Defaults to the
   * sandbox id, which always resolves.
   */
  alias?: string;
  /**
   * Only place this sandbox on a node carrying every one of these labels,
   * e.g. `{ rack: "b7" }`. Burrow has no regions: operators label nodes with
   * `burrowd serve --label`, and this is how a caller says which hardware its
   * workload belongs on. No node carrying all of them fails with
   * `failed_precondition` rather than landing somewhere else.
   */
  nodeLabels?: Record<string, string>;
  /**
   * Allocated public IPs to attach once it is up. A static address places the
   * sandbox on the node it reaches.
   */
  publicIps?: string[];
  /**
   * Whether callers may run commands in this sandbox. Omitted allows exec,
   * which is the default for every sandbox.
   */
  exec?: ExecOptions;
  /**
   * What callers may do to this sandbox's filesystem. Omitted allows
   * everything; passing it at all is what turns the limits on.
   */
  fs?: FsOptions;
  /** Tags, at most 16. Keys are 1..64 bytes, values up to 256. */
  tags?: Record<string, string>;
}

/** Options for {@link Sandbox.get}. */
export interface GetOptions extends CallOptions, HandleOptions {
  /** Id or name. Every reference the API takes accepts either. */
  id: string;
}

/**
 * Options for {@link Sandbox.getOrCreate}.
 *
 * Everything {@link CreateOptions} takes, plus the hooks. The create options
 * apply only when the sandbox turns out not to exist; a sandbox that is already
 * there is returned as it is, rather than being reconfigured.
 */
export interface GetOrCreateOptions extends CreateOptions {
  /** Called with the sandbox when this call is the one that created it. */
  onCreate?: (sandbox: Sandbox) => void | Promise<void>;
  /**
   * Resume the sandbox if it is suspended. Defaults to false: a suspended
   * sandbox is handed back as it is, and the first call that needs a running
   * VM resumes it anyway unless `autoResume` is off.
   */
  resume?: boolean;
}

/** Options for {@link Sandbox.list}. */
export interface ListOptions extends CallOptions, HandleOptions {
  /** One tag as `"key=value"`, matched exactly. Omitted lists everything. */
  tag?: string;
}

/**
 * Options for {@link Sandbox.updateLifetime}. An omitted field is left where
 * it is, so `0` keeps meaning "unlimited" here as it does on create.
 */
export interface UpdateLifetimeOptions extends CallOptions, LifetimeOptions {
  /** How long the sandbox's snapshots are kept, held to a create's rules. */
  snapshots?: SnapshotPolicyOptions;
}

/** Options for {@link Sandbox.updateAccessPolicy}. */
export interface UpdateAccessOptions extends CallOptions {
  /**
   * Replaces the exec policy wholesale. Omitted leaves it exactly as it is.
   *
   * Unlike create, where an omitted section means "no restriction", omitting
   * one here means "do not touch it", so tightening `fs` cannot silently
   * re-open exec.
   */
  exec?: ExecOptions;
  /**
   * Replaces the file policy wholesale: every field is replaced together, so
   * restate the ones you want kept. Omitted leaves the policy as it is.
   */
  fs?: FsOptions;
}

/** Options for {@link Sandbox.move}. */
export interface MoveOptions extends CallOptions {
  /** The node to move to. Omitted places it like a create. */
  nodeId?: string;
  /** Labels the destination must carry, when no node is named. */
  nodeLabels?: Record<string, string>;
}

/** Options for {@link Sandbox.fork}. */
export interface ForkOptions extends CallOptions {
  /**
   * Name for the child. A fork never inherits its source's name, because a
   * name belongs to one sandbox.
   */
  name?: string;
  /**
   * Replaces the source's egress policy on the child. Omitted inherits it,
   * which is the usual case: a fork is meant to be the same sandbox again.
   */
  networkPolicy?: NetworkInput;
  /** Private networks the child joins instead of the source's. */
  networks?: ReadonlyArray<string | NetworkMembership>;
  /** Name the child answers to on those networks. */
  alias?: string;
  /** Replaces the source's exec policy on the child. Omitted inherits it. */
  exec?: ExecOptions;
  /** Replaces the source's fs policy on the child. Omitted inherits it. */
  fs?: FsOptions;
  /**
   * Require the source's node to carry every one of these labels. A fork is
   * built where its source's state already is, so this cannot move the child:
   * a source on a node without them fails with `failed_precondition`.
   */
  nodeLabels?: Record<string, string>;
}

/** Options for {@link Sandbox.getCommand}. */
export interface GetCommandOptions extends CallOptions {
  /** Output offset to replay from, stdout and stderr counted together. */
  fromOffset?: number;
}

/** Options for {@link Sandbox.exposePort}. */
export interface ExposePortOptions extends CallOptions {
  /** Host port to publish on. Omitted lets the node pick one. */
  hostPort?: number;
  /** Forward UDP rather than TCP. */
  udp?: boolean;
}

/**
 * What the sandbox knows about a command it has run.
 *
 * Every byte a command prints is kept on the node until
 * {@link Sandbox.pruneCommands} removes it, unless the command asked for its
 * log to rotate.
 */
export interface CommandInfo {
  cmdId: string;
  /** argv, as the guest ran it. */
  cmd: string[];
  /** The user it ran as. Empty means root. */
  user: string;
  state: CommandState;
  /** Meaningful only once `state` is `"exited"`. */
  exitCode: number;
  startedAt: Date;
  /** `null` while the command is still running. */
  endedAt: Date | null;
  /** Output held on the node for a later {@link Sandbox.getCommand} to replay. */
  bufferedBytes: number;
  /** The signal that ended the command; 0 if none did. */
  exitSignal: number;
  /**
   * Output produced in all, stdout and stderr together: the offset a reader
   * that is up to date resumes from.
   */
  outputBytes: number;
}

export type CommandState = "running" | "exited" | "unknown";

/** A user created inside the guest. */
export interface GuestUser {
  username: string;
  uid: number;
  gid: number;
  /** The user's home, created 0700 so other sandbox users cannot read it. */
  home: string;
}

/** A group created inside the guest. */
export interface GuestGroup {
  groupname: string;
  gid: number;
  /**
   * A directory the group's members share, group-owned and 2770 setgid so a
   * file created inside it stays readable by the rest of the group.
   */
  sharedDir: string;
}

export interface PortMapping {
  guestPort: number;
  hostPort: number;
  /** Whether the mapping forwards UDP rather than TCP. */
  udp: boolean;
  /** Address to reach the published port from outside the sandbox. */
  url: string;
  /**
   * Stable per-sandbox URL through the edge router on the node holding the
   * sandbox, `http://<port>-<sandbox-id>.<edge-domain>/`. Traffic arriving on it
   * for a suspended sandbox wakes it. Absent when that node runs no edge, which
   * means it has no hostname routing and {@link url} is the whole answer, and
   * always absent for a UDP mapping, which the edge cannot route.
   */
  edgeUrl?: string;
}

/**
 * A sandbox reachable through a tailcat address.
 *
 * The address is the credential: any `tailcat` client holding it can connect,
 * unless `allowedClients` narrows that. Treat it as a secret.
 */
export interface Share {
  address: string;
  /** Guest TCP ports reachable through the share; empty means every port. */
  ports: number[];
  /** `nodekey:<hex>` of each admitted client; empty admits anyone. */
  allowedClients: string[];
  /** When the current keys were issued. */
  createdAt: Date;
  /** Guest UDP ports reachable through the share; none unless listed or `allUdp`. */
  udpPorts: number[];
  allUdp: boolean;
  /**
   * Whether the guest really sees each client's own public IPv4 as the
   * packet source. A node that cannot carry the reply path serves from the
   * gateway whatever was asked for.
   */
  transparentIp: boolean;
}

export interface ShareOptions extends CallOptions {
  /** Guest TCP ports reachable through the share. Omitted shares every port. */
  ports?: number[];
  /** Client node keys admitted, as `nodekey:<hex>`. Omitted admits anyone. */
  allowedClients?: string[];
  /** Issue new keys, and so a new address, to an existing share. */
  rotate?: boolean;
  /** Guest UDP ports reachable through the share. Omitted shares no UDP. */
  udpPorts?: number[];
  /** Share every UDP port. */
  allUdp?: boolean;
  /**
   * Source connections from the client's own public IPv4, which is what the
   * guest sees by default. `false` sources them from the gateway.
   */
  transparentIp?: boolean;
}

/** A node's disk, as its last heartbeat reported it. */
export interface DiskCapacity {
  freeBytes: number;
  totalBytes: number;
  /** What the node keeps free and promises to no sandbox. */
  reserveBytes: number;
  /** Disk promised to sandboxes and not yet written. */
  unwrittenBytes: number;
  /** How far promises may exceed free space; 1 means never. */
  overcommit: number;
}

export interface NodeInfo {
  id: string;
  address: string;
  hostname: string;
  totalVcpus: number;
  totalMemoryMib: number;
  freeMemoryMib: number;
  runningSandboxes: number;
  healthy: boolean;
  draining: boolean;
  lastHeartbeatAt: Date;
  /**
   * What the operator labelled this node with. Constrain a create to hardware
   * carrying particular labels with {@link CreateOptions.nodeLabels}.
   */
  labels: Record<string, string>;
  /** Cpu architecture. Durable snapshots only restore on a matching node. */
  arch: string;
  /** Each offered hypervisor's version. Saved state needs an exact match. */
  hypervisorVersions: Record<string, string>;
  /** Absent for a node that does not report disk. */
  disk?: DiskCapacity;
  /** Free disk is below the reserve; the node refuses creates until it is not. */
  diskLow: boolean;
}

/** Options for {@link Burrow.drainNode}. */
export interface DrainOptions extends CallOptions {
  /** Also suspend every sandbox the node runs, so the drain leaves nothing live. */
  suspend?: boolean;
  /** Drain although sandboxes here hold public IPs; they stay on this node. */
  keepPinned?: boolean;
}

/** One recorded egress attempt or DNS lookup. */
export interface AuditEvent {
  at: Date;
  sandboxId: string;
  sourceIp: string;
  destination: string;
  /** Hostname when burrow could identify one, otherwise empty. */
  host: string;
  port: number;
  allowed: boolean;
  reason: string;
  bytesSent: number;
  bytesReceived: number;
  nodeId: string;
}

export interface AuditQuery extends CallOptions {
  sandboxId?: string;
  /** Only attempts that were refused. */
  deniedOnly?: boolean;
  /** Lower bound. */
  since?: Date | number;
  limit?: number;
}

/**
 * What happened to a sandbox. `recovered` is one a node found on restart;
 * `ip_attached` and `ip_detached` carry the address as their detail.
 */
export type EventKind =
  | "created"
  | "started"
  | "agent_ready"
  | "stopped"
  | "destroyed"
  | "snapshot_created"
  | "recovered"
  | "ip_attached"
  | "ip_detached"
  | "unknown";

/**
 * One thing that happened to a sandbox, from the fleet's lifecycle log.
 *
 * Each event carries the sandbox's cpu and network totals at that instant, so
 * the interval between two events is time spent in one state at one shape.
 */
export interface LifecycleEvent {
  /** Position in the fleet-wide log. Pass it as `after` to resume. */
  seq: number;
  nodeId: string;
  /** Position in the recording node's own log. */
  nodeSeq: number;
  at: Date;
  sandboxId: string;
  kind: EventKind;
  state: SandboxState;
  /**
   * How a VM started (`boot`, `restore`, `resume`) or stopped (`suspended`,
   * `deleted`, `stopped`, `failed`, or `lost` for a VM a node found gone on
   * restart), what a sandbox was created from (`fork:<id>`,
   * `snapshot:<id>`), or the snapshot a commit produced.
   */
  detail: string;
  template: string;
  tags: Record<string, string>;
  cpuUsageUsec: number;
  rxBytes: number;
  txBytes: number;
  vcpus: number;
  memoryMib: number;
}

/** Options for {@link Burrow.events}. */
export interface EventsOptions extends CallOptions {
  /** Start after this `seq`. Omitted replays from the oldest event kept. */
  after?: number;
  /** Only events for this sandbox, by id or name. */
  sandboxId?: string;
  /** Keep yielding new events after the replay instead of ending. */
  follow?: boolean;
  /** Cap on replayed events. Omitted lets the server choose. */
  limit?: number;
}

/**
 * What a sandbox was doing over an interval. Coarser than its state: paused
 * and suspended both hold memory and no cpu, failed and stopped both hold a
 * disk and nothing else.
 */
export type UsageState = "running" | "suspended" | "stopped" | "unknown";

/** What {@link Burrow.usage} sums by. `tag:<key>` groups by that tag's value. */
export type UsageGroup = "sandbox" | "template" | "node" | "state" | `tag:${string}`;

/** Options for {@link Burrow.usage}. */
export interface UsageQuery extends CallOptions {
  /** Intervals that start at or after this. Omitted leaves the window open. */
  from?: Date | number;
  /** Intervals that start before this. */
  to?: Date | number;
  /** One sandbox, by id or by the name of one that still exists. */
  sandboxId?: string;
  /** Only sandboxes that carried every one of these tags. */
  tags?: Record<string, string>;
  /** Given, the report holds sums per group and state instead of intervals. */
  groupBy?: UsageGroup;
  /** Continue an export after this interval id, from `nextAfterId`. */
  afterId?: number;
  /** Intervals per page. Omitted lets the server choose; sums are never paged. */
  limit?: number;
  /**
   * Count the stretch since each open interval began, up to the last
   * heartbeat. Defaults to true; never applies with `afterId`.
   */
  includeOpen?: boolean;
}

/**
 * One stretch a sandbox spent in one state at one shape, from the usage
 * ledger. The usage is the difference of the sandbox's totals at the two
 * bounds, so it survives the sandbox and its node.
 */
export interface UsageInterval {
  /** Ledger row id, ascending in write order. 0 for an open interval. */
  id: number;
  sandboxId: string;
  nodeId: string;
  template: string;
  tags: Record<string, string>;
  state: UsageState;
  vcpus: number;
  memoryMib: number;
  startedAt: Date;
  /** `null` while the interval is open. */
  endedAt: Date | null;
  cpuUsageUsec: number;
  rxBytes: number;
  txBytes: number;
  /**
   * The event kind that ended the state, `checkpoint` for the hourly split,
   * or `write_off` for a node that went silent. Empty while open.
   */
  closedBy: string;
  open: boolean;
}

/** Intervals summed for one group in one state. */
export interface UsageSum {
  group: string;
  state: UsageState;
  intervals: number;
  durationMs: number;
  /** Duration weighted by vCPUs, for vCPU-hours. */
  vcpuMs: number;
  /** Duration weighted by memory, for GiB-hours. */
  memoryMibMs: number;
  cpuUsageUsec: number;
  rxBytes: number;
  txBytes: number;
}

export interface UsageReport {
  intervals: UsageInterval[];
  sums: UsageSum[];
  /** Pass as `afterId` for the next page; 0 when there is none. */
  nextAfterId: number;
}
