import type { Writable } from "node:stream";

// Type-only, so it is erased rather than becoming an import cycle.
import type { Sandbox } from "./sandbox.js";

/** Egress policy for a sandbox. */
export type NetworkMode = "none" | "allowlist" | "open";

export type SandboxState =
  | "creating"
  | "running"
  | "paused"
  | "suspended"
  | "stopping"
  | "destroyed"
  | "failed"
  | "unknown";

/**
 * The coarse lifecycle a sandbox is in, a narrower view of
 * {@link SandboxState}. `suspended` and `paused` both read as `stopped`:
 * either way the sandbox must be resumed before it will run anything.
 */
export type SandboxStatus =
  | "pending"
  | "running"
  | "stopping"
  | "stopped"
  | "failed";

/** A credential the host attaches to egressing requests on the sandbox's behalf. */
export interface HeaderInjection {
  /** Domain glob, matched exactly like `allowDomains`. */
  domain: string;
  /** Header name, an RFC 9110 token. */
  name: string;
  /**
   * Secret value. It never leaves the node: every read of a policy returns it
   * redacted, so code in the guest can use the credential without holding it.
   */
  value: string;
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
  /** Domain glob, matched exactly like `allowDomains`. */
  domain: string;
  match?: RequestMatch;
  /** Headers set on the request, replacing whatever the guest sent. */
  setHeaders?: Record<string, string>;
  forward?: ForwardRequest;
}

/** Egress policy in full. The shorthand `network: "allowlist"` sets `mode`. */
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
  /**
   * Terminate the sandbox's TLS so the host named inside the session is
   * checked too, not just the SNI. Required by `rules` and `injectHeaders`.
   */
  inspectTls?: boolean;
  /**
   * What the host does to the requests it inspects, in order. Requires
   * `inspectTls`. At most 32.
   */
  rules?: RequestRule[];
  /**
   * Credentials brokered on the host side, the shorthand for a rule with no
   * matcher that sets one header. They are appended after `rules`, since a
   * rule with no matcher claims every request to its domain.
   */
  injectHeaders?: HeaderInjection[];
}

/**
 * A rewrite applied to inspected requests for one domain.
 *
 * The host sets these headers on the requests the rule selects, replacing
 * whatever the guest sent under the same name.
 */
export interface DomainTransform {
  headers: Record<string, string>;
}

/**
 * What a domain is allowed to do, in the object form of `networkPolicy`.
 *
 * Without a `match` the rule applies to every request to the domain, so it
 * shadows anything written after it for the same domain. Give a domain a list
 * of rules to have several, narrowest first.
 */
export interface DomainRule {
  /** Which requests this rule applies to. A matcher never blocks. */
  match?: RequestMatch;
  /** Rewrites applied to the requests this rule selects. Forces inspection. */
  transform?: DomainTransform[];
  /**
   * Send the requests this rule selects to an endpoint you control instead of
   * to the origin. An `http://` or `https://` URL with no query string.
   * Forces inspection.
   */
  forwardURL?: string;
  /**
   * Shared secret sent to `forwardURL` as `burrow-forwarded-secret`. It
   * authenticates the node, not the sandbox. Over `https://` it is protected
   * in transit; over `http://` the endpoint must be reachable only by the
   * node. Burrow's own, since it has no OIDC issuer to sign with.
   */
  forwardSecret?: string;
}

/**
 * The shorthand policy shapes, for code written against SDKs that use them.
 *
 * `"allow-all"` is `mode: "open"`, `"deny-all"` is `mode: "none"`, and the
 * object form is an allowlist: `allow` names domains, `subnets` names ranges.
 */
export type NetworkPolicyShorthand =
  | "allow-all"
  | "deny-all"
  | {
      /**
       * Domains reachable, as a list or as a map carrying per-domain rules.
       * A domain may carry several rules, evaluated in the order written.
       */
      allow?: string[] | Record<string, DomainRule | DomainRule[]>;
      subnets?: { allow?: string[]; deny?: string[] };
    };

/** Every accepted spelling of an egress policy. */
export type NetworkInput =
  | NetworkMode
  | NetworkPolicyOptions
  | NetworkPolicyShorthand;

/** Egress policy as the server reports it. Injected values arrive redacted. */
export interface NetworkPolicy {
  mode: NetworkMode;
  allowDomains: string[];
  allowCidrs: string[];
  allowPorts: number[];
  denyCidrs: string[];
  inspectTls: boolean;
  /** What the host does to inspected requests, in order. Secrets are redacted. */
  rules: RequestRule[];
  /**
   * The subset of `rules` that is a matcher-less header injection, kept for
   * code written before rules existed. Values arrive redacted.
   */
  injectHeaders: HeaderInjection[];
}

/** Machine shape and lifetime. Every `0` means "the server's default". */
export interface ResourceOptions {
  vcpus?: number;
  memoryMib?: number;
  diskMib?: number;
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
   * Sweep snapshots of this sandbox this many seconds after they were last
   * used, where a use is a sandbox created from one. 0 keeps them until
   * something deletes them.
   */
  snapshotExpirationSecs?: number;
  /**
   * Keep only this many snapshots of the sandbox, evicting the oldest as a new
   * one is taken. 1 to 10; 0 is unlimited.
   */
  keepLastSnapshots?: number;
  /**
   * Let a snapshot that `keepLastSnapshots` evicts live out its expiration
   * instead of being deleted at once. Needs both `keepLastSnapshots` and
   * `snapshotExpirationSecs`; without an expiry the server refuses it, since
   * nothing would ever reclaim what was kept.
   */
  keepEvictedSnapshots?: boolean;
}

export interface ResourcePolicy {
  vcpus: number;
  memoryMib: number;
  diskMib: number;
  maxLifetimeSecs: number;
  idleSuspendSecs: number;
  suspendedTtlSecs: number;
  snapshotExpirationSecs: number;
  keepLastSnapshots: number;
  keepEvictedSnapshots: boolean;
}

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
  /** Defaults to true. `false` refuses exec, terminals and `runCode`. */
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

export interface ExecPolicy {
  allowExec: boolean;
}

export interface FsPolicy {
  allowUpload: boolean;
  allowDownload: boolean;
  pathScopes: string[];
  maxUploadBytes: number;
}

export interface SandboxPolicy {
  resources: ResourcePolicy;
  /** Absent when the sandbox places no limit on exec. */
  exec?: ExecPolicy;
  /** Absent when the sandbox places no limit on file access. */
  fs?: FsPolicy;
  network: NetworkPolicy;
  networks: NetworkMembership[];
  /** Volumes the sandbox has mounted. */
  volumes: VolumeMount[];
}

/**
 * What a sandbox has actually consumed.
 *
 * Accumulated across every VM it has run, so a suspend and a resume do not
 * reset it. A sandbox that has not run anything reports zeroes.
 */
export interface Usage {
  /**
   * Host CPU in microseconds, read from the sandbox's cgroup. That covers the
   * whole VMM: the guest's vCPU threads and Firecracker's own work for them.
   */
  cpuUsageUsec: number;
  /** Bytes delivered to the guest, counted at its tap. */
  rxBytes: number;
  /** Bytes the guest sent, counted at the same place. */
  txBytes: number;
}

/**
 * One VM boot inside a sandbox's life.
 *
 * A sandbox outlives its VMs: a stop ends one and a resume starts the next, and
 * a fork or a create from a snapshot starts one from state written elsewhere.
 */
export interface Session {
  id: string;
  sandboxId: string;
  /** RFC 3339. */
  startedAt: string;
  /**
   * RFC 3339. Empty while the session is open, and empty for one the node died
   * during: nothing recorded when that VM stopped.
   */
  endedAt: string;
  startedBy: SessionStart;
  /** Empty while the session is open. */
  endedBy: SessionEnd | "";
}

/**
 * How a VM started. `boot` is from a template, `restore` from a fork or a
 * snapshot, `resume` from the sandbox's own stop state.
 */
export type SessionStart = "boot" | "restore" | "resume" | "unknown";

/** How a VM stopped. `unknown` is a session that was open when the node died. */
export type SessionEnd = "suspended" | "deleted" | "failed" | "unknown";

export interface SandboxInfo {
  id: string;
  /** The name it was created with, or `""` when it was created without one. */
  name: string;
  nodeId: string;
  template: string;
  state: SandboxState;
  createdAt: string;
  /** Address the sandbox holds on the networks it joined. */
  guestIp: string;
  /** Tags. `metadata` is the same map under its original name. */
  tags: Record<string, string>;
  metadata: Record<string, string>;
  policy: SandboxPolicy;
  /**
   * Whether the node hosting the sandbox has missed its heartbeats. When true,
   * `state` is a stale reading and calls fail until the node returns.
   */
  unreachable: boolean;
  /** What the sandbox has consumed, as of this reading. */
  usage: Usage;
}

export interface CreateOptions {
  /**
   * Name for the sandbox, usable anywhere its id is, and the only identity a
   * caller chooses: ids are generated by the server. 1 to 63 characters of
   * lowercase letters, digits and `-`, not starting or ending with `-`.
   *
   * Unique across the fleet, so a name already in use fails with
   * `already_exists`, and fixed once the sandbox exists.
   */
  name?: string;
  /** Guest image to boot. Defaults to `"default"`. */
  template?: string;
  /**
   * Snapshot id to start from. The sandbox **restores** that state instead of
   * booting, so it arrives with the snapshot's processes and memory, and
   * `template`, `vcpus` and `memoryMib` may not disagree with what the
   * snapshot holds. Placed on the node holding it: snapshots do not travel.
   */
  snapshot?: string;
  /** The same thing under the name an image-shaped SDK uses. */
  image?: string;
  vcpus?: number;
  memoryMib?: number;
  /** Machine shape and lifetime. Wins over `vcpus` and `memoryMib`. */
  resources?: ResourceOptions;

  /**
   * Egress policy. Defaults to `"none"`: a sandbox with no network at all.
   * Network access is opt-in, not opt-out. Pass a mode for the common case, or
   * an object for the full policy.
   */
  network?: NetworkInput;
  /** The same thing under its longer name. `network` wins if both are given. */
  networkPolicy?: NetworkInput;
  /** Shorthand for `network.allowDomains`. */
  allowDomains?: string[];
  /** Shorthand for `network.allowCidrs`. */
  allowCidrs?: string[];
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
  /** The same map under its original name. `tags` wins if both are given. */
  metadata?: Record<string, string>;
  /**
   * Environment for every command this handle runs, under whatever a single
   * command passes.
   *
   * Held by the handle, not by the sandbox: there is nowhere on the server to
   * put it, so a handle from {@link Sandbox.get} in another process does not
   * have it. Bake anything that has to survive into the template.
   */
  env?: Record<string, string>;
  /**
   * Resume a suspended sandbox and retry once when a call needs it running.
   * Defaults to true.
   */
  autoResume?: boolean;
  /** Milliseconds to wait for the sandbox to boot. */
  timeoutMs?: number;
  signal?: AbortSignal;
}

/** Options for {@link Sandbox.get}. */
export interface GetOptions {
  /** Id or name. Every reference the API takes accepts either. */
  sandboxId?: string;
  /** The same thing under a shorter name. */
  id?: string;
  /** The sandbox's name, when that is what you have. */
  name?: string;
  /** Resume a suspended sandbox on demand. Defaults to true. */
  autoResume?: boolean;
  signal?: AbortSignal;
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
  /** Called with the sandbox whenever this handle resumes it. */
  onResume?: (sandbox: Sandbox) => void | Promise<void>;
  /**
   * Resume the sandbox if it is stopped. Defaults to false: a stopped sandbox
   * is handed back stopped, and the first call that needs a running VM resumes
   * it anyway unless `autoResume` is off.
   */
  resume?: boolean;
}

/** Options for {@link Sandbox.list}. */
export interface ListOptions {
  /** One tag as `"key=value"`, matched exactly. Omitted lists everything. */
  tag?: string;
  signal?: AbortSignal;
}

/**
 * Options for {@link Sandbox.update}.
 *
 * Only what the control plane can change on a live sandbox is here. The machine
 * shape is not: a running VM's configuration is fixed, and a restore takes it
 * from the snapshot. The clocks the sandbox is measured against do move.
 */
export interface UpdateOptions {
  /**
   * Hard cap on how long the sandbox may live, in seconds from its creation.
   * 0 is unlimited. Omitted leaves it where it is.
   */
  maxLifetimeSecs?: number;
  /** Suspend after this many idle seconds. 0 never suspends. */
  idleSuspendSecs?: number;
  /** Delete a sandbox that has been suspended this long. 0 keeps it. */
  suspendedTtlSecs?: number;
  /**
   * Replaces the tag set wholesale: an omitted tag is a tag removed, and `{}`
   * clears them.
   */
  tags?: Record<string, string>;
  /**
   * Replaces the egress policy wholesale: an omitted field is an allowance
   * withdrawn, which is what makes "lock this sandbox down" one call.
   */
  networkPolicy?: NetworkInput;
  /** The same thing under a shorter name. */
  network?: NetworkInput;
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
  signal?: AbortSignal;
}

/** Options for {@link Sandbox.fork}. */
export interface ForkOptions {
  /** Id for the child. Omitted has one generated. */
  sandboxId?: string;
  /** The same thing under a shorter name. */
  id?: string;
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
  /** The same thing under a shorter name. */
  network?: NetworkInput;
  /** Private networks the child joins instead of the source's. */
  networks?: ReadonlyArray<string | NetworkMembership>;
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
  signal?: AbortSignal;
}

/** Options for the static {@link Sandbox.fork}. */
export interface ForkSourceOptions extends ForkOptions {
  /** The sandbox to fork, by id or by name. */
  source: string;
}

export interface RunOptions {
  env?: Record<string, string>;
  cwd?: string;
  /**
   * Guest user to run as. Defaults to root, which is what every command ran
   * as before this existed.
   *
   * The user has to exist already; {@link Sandbox.createUser} creates one.
   * `HOME`, `USER`, `LOGNAME` and the working directory follow the user unless
   * `env` or `cwd` say otherwise.
   */
  user?: string;
  /** Allocate a pty, so programs behave as if attached to a terminal. */
  pty?: boolean;
  rows?: number;
  cols?: number;
  timeoutMs?: number;
  /** Called with each chunk of stdout as it arrives. */
  onStdout?: (chunk: string) => void;
  /** Called with each chunk of stderr as it arrives. */
  onStderr?: (chunk: string) => void;
  /**
   * Throw `CommandFailedError` on a non-zero exit instead of returning it.
   * Defaults to false, matching how shells report failures.
   */
  check?: boolean;
}

export interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  /** True when `exitCode === 0`. */
  success: boolean;
}

/** Options accepted by every call, alongside whatever else it takes. */
export interface CallOptions {
  /** Cancels the call. An aborted call rejects with code `"cancelled"`. */
  signal?: AbortSignal;
}

/** Options for {@link Sandbox.runCommand}. */
export interface RunCommandOptions extends RunOptions {
  /**
   * Run through `/bin/sh -c`, so pipes and redirection work. Defaults to true
   * when the command is a bare string, false once `args` are given.
   */
  shell?: boolean;
  /** Set to false to skip the auto-resume retry for this call. */
  autoResume?: boolean;
  signal?: AbortSignal;
}

/** The object form of {@link Sandbox.runCommand}. */
export interface RunCommandParams extends RunCommandOptions {
  cmd: string;
  args?: string[];
  /** Return a handle immediately instead of waiting for the command to exit. */
  detached?: boolean;
  /** Stream the command's stdout here as it arrives, e.g. `process.stdout`. */
  stdout?: Writable;
  /** Stream the command's stderr here as it arrives. */
  stderr?: Writable;
}

/**
 * A command that has run to completion.
 *
 * `stdout()` and `stderr()` are methods rather than fields, so the same code
 * reads a finished command and a detached one; both return the whole stream as
 * UTF-8 text.
 */
export interface FinishedCommand {
  exitCode: number;
  /** True when `exitCode === 0`. */
  success: boolean;
  stdout(): string;
  stderr(): string;
}

/**
 * A command still running, returned by `runCommand({ detached: true })` and by
 * {@link Sandbox.getCommand}.
 *
 * Read `logs()` as it goes, or `wait()` for the finished result.
 */
export interface DetachedCommand {
  sandboxId: string;
  /**
   * The command's id in the sandbox.
   *
   * Stable and addressable: hand it to {@link Sandbox.getCommand} from another
   * process to follow, wait on or signal the same command.
   */
  cmdId: string;
  /** Interleaved stdout and stderr, in the order they arrived. */
  logs(): AsyncIterable<OutputChunk>;
  /** Waits for the command to exit and returns what it produced. */
  wait(): Promise<FinishedCommand>;
  /**
   * Signals the command, without waiting. Defaults to SIGKILL.
   *
   * Only one failure is swallowed: the command had already exited, which is
   * the state the signal asked for. Everything else rejects, and with nothing
   * awaiting it that surfaces as an unhandled rejection rather than as
   * silence: `permission_denied` when the exec policy forbids commands,
   * `failed_precondition` when the sandbox is suspended, `not_found` for a
   * command the guest has evicted, and transport failures. Use {@link killed}
   * to handle any of those.
   */
  kill(signal?: number): void;
  /**
   * The awaitable {@link kill}: resolves once the node has delivered the
   * signal, and rejects on every failure above, including a command that had
   * already exited.
   */
  killed(signal?: number): Promise<void>;
}

/**
 * What the sandbox knows about a command it has run.
 *
 * The guest keeps the last 256 KiB of each command's output and the 64 most
 * recent finished commands. Past either bound the command is gone: its output
 * replays from where the buffer still reaches, and an evicted command is no
 * longer listed.
 */
export interface CommandInfo {
  cmdId: string;
  /** argv, as the guest ran it. */
  cmd: string[];
  /** The user it ran as. Empty means root. */
  user: string;
  state: "running" | "exited" | "unknown";
  /** Meaningful only once `state` is `"exited"`. */
  exitCode: number;
  startedAt: Date;
  /** `null` while the command is still running. */
  endedAt: Date | null;
  /** Output still held for a later `logs()`. */
  bufferedBytes: number;
}

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

/** Options for {@link Sandbox.downloadFile}. */
export interface DownloadFileOptions {
  /** Create the destination's parent directories. Defaults to true. */
  mkdirRecursive?: boolean;
  signal?: AbortSignal;
}

/** One file for {@link Sandbox.writeFiles}. */
export interface FileWrite {
  path: string;
  /** Text or bytes. `contents` is accepted as a synonym. */
  content?: string | Uint8Array;
  contents?: string | Uint8Array;
  /** Unix mode for a created file. 0 means 0644. */
  mode?: number;
}

/** Names one file, for the object form of the read methods. */
export interface FileRef {
  path: string;
  signal?: AbortSignal;
}

/** One chunk of a streaming command. */
export type OutputChunk =
  | { type: "stdout"; data: string }
  | { type: "stderr"; data: string }
  | { type: "exit"; exitCode: number };

export interface DirEntry {
  name: string;
  isDir: boolean;
  size: number;
  mode: number;
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
   * for a stopped sandbox wakes it. Absent when that node runs no edge, which
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
  /** RFC 3339; when the current keys were issued. */
  createdAt: string;
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

export interface ShareOptions {
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
   * Source connections from the gateway instead of from the client's own
   * public IPv4, which is what the guest sees by default.
   */
  noTransparentIp?: boolean;
  signal?: AbortSignal;
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
  /**
   * What the operator labelled this node with. Constrain a create to hardware
   * carrying particular labels with {@link CreateOptions.nodeLabels}.
   */
  labels: Record<string, string>;
}

/** A filesystem change reported by {@link Sandbox.watch}. */
export interface WatchEvent {
  type: "created" | "modified" | "deleted";
  path: string;
  isDir: boolean;
}

export interface WatchOptions {
  /** Descend into subdirectories. */
  recursive?: boolean;
  /** How often the guest re-scans, in milliseconds. Defaults to 500. */
  intervalMs?: number;
  onEvent?: (event: WatchEvent) => void;
  onError?: (err: Error) => void;
}

/** Handle returned by {@link Sandbox.watch}. */
export interface Watcher {
  /** Stops watching. */
  stop(): void;
  /** Async iteration over events, as an alternative to `onEvent`. */
  [Symbol.asyncIterator](): AsyncIterator<WatchEvent>;
}

/** One recorded egress attempt or DNS lookup. */
export interface AuditEvent {
  at: string;
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

export interface AuditQuery {
  sandboxId?: string;
  /** Only attempts that were refused. */
  deniedOnly?: boolean;
  /** RFC 3339 lower bound. */
  since?: string;
  limit?: number;
}
