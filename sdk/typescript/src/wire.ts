/**
 * Conversions between what the wire carries and what the SDK hands out:
 * proto enum names and unix milliseconds on one side, lowercase unions and
 * `Date`s on the other.
 */

import type { KernelInfo } from "./types.js";

/**
 * Maps a wire enum name onto the SDK's lowercase union: `SANDBOX_STATE_RUNNING`
 * with prefix `SANDBOX_STATE_` reads as `running`. A value this SDK has no
 * name for reads as `unknown` rather than passing a string through that
 * callers branch on.
 */
export function enumOf<T extends string>(
  raw: unknown,
  prefix: string,
  known: readonly T[],
): T | "unknown" {
  const name = String(raw ?? "").replace(prefix, "").toLowerCase();
  return (known as readonly string[]).includes(name) ? (name as T) : "unknown";
}

/** The wire name of one of the SDK's lowercase union values. */
export function enumTo(prefix: string, value: string): string {
  return prefix + value.toUpperCase();
}

export function dateOf(unixMs: unknown): Date {
  return new Date(Number(unixMs ?? 0));
}

/** `null` for a stamp the server left at 0: open, never, or not yet. */
export function dateOrNull(unixMs: unknown): Date | null {
  const ms = Number(unixMs ?? 0);
  return ms > 0 ? new Date(ms) : null;
}

/** Unix milliseconds for a `Date`, a number already in them, or 0 when unset. */
export function msOf(at: Date | number | undefined): number {
  if (at instanceof Date) return at.getTime();
  return at ?? 0;
}

/** @internal One `Kernel` message; `null` when absent. */
export function toKernelInfo(raw: any): KernelInfo | null {
  if (!raw) return null;
  const caps = raw.capabilities ?? {};
  return {
    name: raw.name ?? "",
    digest: raw.digest ?? "",
    version: raw.version ?? "",
    arch: raw.arch ?? "",
    capabilities: {
      kvm: Boolean(caps.isKvmBuiltIn),
      virtioMem: Boolean(caps.isVirtioMemBuiltIn),
      vsock: Boolean(caps.isVsockBuiltIn),
      virtioBlk: Boolean(caps.isVirtioBlkBuiltIn),
      ext4: Boolean(caps.isExt4BuiltIn),
    },
    detectedFrom: raw.detectedFrom ?? "",
  };
}
