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
    return this.code === "failed_precondition" && /suspend/i.test(this.message);
  }

  /**
   * True when a signal was refused because the command had already exited.
   *
   * The one refusal a `kill()` can ignore, since it asked for a state the
   * command is already in. Narrower than the code alone: a suspended sandbox
   * refuses a signal with `failed_precondition` too, and that one is a real
   * failure to deliver.
   */
  get isAlreadyExited(): boolean {
    return this.code === "failed_precondition" && !this.isSuspended;
  }
}

/** Thrown by `commands.run` when a command exits non-zero and `check` is set. */
export class CommandFailedError extends BurrowError {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;

  constructor(command: string, exitCode: number, stdout: string, stderr: string) {
    super(
      `command exited with ${exitCode}: ${command}${
        stderr.trim() ? `\n${stderr.trim()}` : ""
      }`,
      "internal",
    );
    this.name = "CommandFailedError";
    this.exitCode = exitCode;
    this.stdout = stdout;
    this.stderr = stderr;
  }
}
