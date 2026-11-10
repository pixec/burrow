import * as grpc from "@grpc/grpc-js";

/** Stable, transport-independent error codes. */
export type BurrowErrorCode =
  | "not_found"
  | "already_exists"
  | "invalid_argument"
  | "failed_precondition"
  | "permission_denied"
  | "unauthenticated"
  | "resource_exhausted"
  | "unavailable"
  | "unimplemented"
  | "deadline_exceeded"
  | "cancelled"
  | "internal";

const CODES: Record<number, BurrowErrorCode> = {
  [grpc.status.NOT_FOUND]: "not_found",
  [grpc.status.ALREADY_EXISTS]: "already_exists",
  [grpc.status.INVALID_ARGUMENT]: "invalid_argument",
  [grpc.status.FAILED_PRECONDITION]: "failed_precondition",
  [grpc.status.PERMISSION_DENIED]: "permission_denied",
  [grpc.status.UNAUTHENTICATED]: "unauthenticated",
  [grpc.status.RESOURCE_EXHAUSTED]: "resource_exhausted",
  [grpc.status.UNAVAILABLE]: "unavailable",
  [grpc.status.UNIMPLEMENTED]: "unimplemented",
  [grpc.status.DEADLINE_EXCEEDED]: "deadline_exceeded",
  [grpc.status.CANCELLED]: "cancelled",
};

/**
 * What the node says about a call that needs a live guest when the sandbox
 * has none, and what the guest says about a signal for a command that has
 * finished. Nothing else in the API uses either phrase, and both are matched
 * only under `failed_precondition`.
 */
const SUSPENDED = "is suspended";
const EXITED = /^command \S+ has (already )?exited$/;

/**
 * An error from burrow.
 *
 * gRPC status codes are mapped to stable string codes so callers can branch on
 * `err.code` without importing grpc-js or knowing the transport.
 */
export class BurrowError extends Error {
  readonly code: BurrowErrorCode;

  constructor(message: string, code: BurrowErrorCode = "internal") {
    super(message);
    this.name = "BurrowError";
    this.code = code;
  }

  static fromGrpc(err: grpc.ServiceError): BurrowError {
    const code = CODES[err.code] ?? "internal";
    // grpc-js prefixes messages with their numeric code; strip it so the
    // message reads as the server wrote it.
    const message = (err.details || err.message || "unknown error").replace(
      /^\d+\s+[A-Z_]+:\s*/,
      "",
    );
    return new BurrowError(message, code);
  }

  /** True when the sandbox is suspended and must be resumed first. */
  get isSuspended(): boolean {
    return this.code === "failed_precondition" && this.message.includes(SUSPENDED);
  }

  /**
   * True when a signal was refused because the command had already exited:
   * the one refusal a `kill()` can ignore, since it asked for a state the
   * command is already in.
   */
  get isAlreadyExited(): boolean {
    return this.code === "failed_precondition" && EXITED.test(this.message);
  }
}
