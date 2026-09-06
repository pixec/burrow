import { Buffer } from "node:buffer";
import { EventEmitter } from "node:events";

import type { Transport } from "./transport.js";

export interface TerminalOptions {
  /** Program to run. Defaults to an interactive shell. */
  command?: string | string[];
  env?: Record<string, string>;
  cwd?: string;
  rows?: number;
  cols?: number;
}

/**
 * A live shell in a sandbox.
 *
 * Unlike {@link Sandbox.exec}, the input side stays open: the caller writes
 * keystrokes and resizes as they happen. That is what makes this usable behind
 * a WebSocket, where a browser terminal is on the other end.
 *
 * ```ts
 * const term = sandbox.terminal({ cols: 120, rows: 40 });
 * term.onData((chunk) => ws.send(chunk));
 * ws.on("message", (data) => term.write(data.toString()));
 * ws.on("close", () => term.kill());
 * ```
 */
export class Terminal {
  private readonly call: any;
  private readonly emitter = new EventEmitter();
  private exited = false;

  /** @internal */
  constructor(transport: Transport, sandboxId: string, options: TerminalOptions) {
    const command = options.command ?? "/bin/sh";
    const cmd = Array.isArray(command) ? command : [command];

    this.call = transport.duplex("Exec");

    this.call.on("data", (msg: any) => {
      if (msg.stdout?.length) {
        this.emitter.emit("data", Buffer.from(msg.stdout).toString("utf8"));
      } else if (msg.stderr?.length) {
        // A pty merges stderr into stdout, so anything arriving here came
        // from a non-pty program; it is still terminal output to the reader.
        this.emitter.emit("data", Buffer.from(msg.stderr).toString("utf8"));
      } else if (typeof msg.exitCode === "number") {
        this.exited = true;
        this.emitter.emit("exit", msg.exitCode);
      }
    });
    this.call.on("error", (err: Error) => {
      if (!this.exited) this.emitter.emit("error", err);
    });
    this.call.on("end", () => {
      if (!this.exited) {
        this.exited = true;
        this.emitter.emit("exit", 0);
      }
    });

    this.call.write({
      start: {
        sandboxId,
        cmd,
        env: options.env ?? {},
        cwd: options.cwd ?? "",
        pty: true,
        rows: options.rows ?? 24,
        cols: options.cols ?? 80,
      },
    });
  }

  /** Sends keystrokes to the terminal. */
  write(data: string | Uint8Array): void {
    if (this.exited) return;
    const bytes = typeof data === "string" ? Buffer.from(data, "utf8") : data;
    this.call.write({ stdin: bytes });
  }

  /** Tells the program its window changed size. */
  resize(rows: number, cols: number): void {
    if (this.exited) return;
    this.call.write({ resize: { rows, cols } });
  }

  /** Sends a signal, e.g. 2 for SIGINT (Ctrl-C at the process level). */
  signal(signal: number): void {
    if (this.exited) return;
    this.call.write({ signal });
  }

  /** Subscribes to terminal output. */
  onData(listener: (chunk: string) => void): this {
    this.emitter.on("data", listener);
    return this;
  }

  onExit(listener: (exitCode: number) => void): this {
    this.emitter.on("exit", listener);
    return this;
  }

  onError(listener: (err: Error) => void): this {
    this.emitter.on("error", listener);
    return this;
  }

  /** Resolves with the exit code when the program ends. */
  wait(): Promise<number> {
    return new Promise((resolve, reject) => {
      if (this.exited) return resolve(0);
      this.emitter.once("exit", resolve);
      this.emitter.once("error", reject);
    });
  }

  /** Closes the input side, as a terminal does on Ctrl-D. */
  end(): void {
    if (!this.exited) this.call.end();
  }

  /** Terminates the program and tears the stream down. */
  kill(): void {
    this.exited = true;
    this.call.cancel();
  }

  async [Symbol.asyncDispose](): Promise<void> {
    this.kill();
  }
}
