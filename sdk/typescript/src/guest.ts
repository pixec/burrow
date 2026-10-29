import type { Direct, Transport } from "./transport.js";

/**
 * @internal What `sandbox.fs` and `sandbox.childProcess` reach their sandbox
 * through. Read live rather than copied, so a handle from `asUser` and the
 * handle it came from never disagree about which sandbox they are on.
 */
export interface GuestLink {
  readonly sandboxId: string;
  /** The guest user file calls and commands act as. Empty is root. */
  readonly user: string;
  /** Environment merged under every command. */
  readonly env: Record<string, string>;
  readonly autoResume: boolean;
  /** Exec, attach and file calls: the node, or the orchestrator relaying. */
  node(): Transport | Direct;
  /** Runs `op`, resuming a suspended sandbox and retrying once. */
  run<T>(op: () => Promise<T>): Promise<T>;
  resume(): Promise<unknown>;
  /** Signals a command by id. A command that had already exited is not an error. */
  signalCommand(cmdId: string, signal: number): Promise<void>;
}
