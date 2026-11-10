import { Buffer } from "node:buffer";

import { withClient } from "./client.js";
import type { TransportOptions } from "./transport.js";
import type { CallOptions } from "./types.js";

/** One step of a template build. */
export interface BuildStep {
  run: string;
}

export interface BuildOptions extends CallOptions {
  /**
   * vCPUs given to the build sandbox. Defaults to 1 for Linux and the restore
   * image's minimum for macOS.
   */
  vcpus?: number;
  /**
   * Memory given to the build sandbox, in MiB. Defaults to 1024 for Linux and
   * the restore image's minimum for macOS.
   */
  memoryMib?: number;
  /**
   * Hypervisor every sandbox from the template runs under: `"firecracker"`,
   * `"cloud-hypervisor"` or `"vz"`. Defaults to the base template's.
   */
  hypervisor?: string;
  /**
   * The installed macOS disk for {@link TemplateBuilder.fromIpsw}, in MiB.
   * Defaults to 65536; macOS needs 28672 to install.
   */
  diskMib?: number;
  /**
   * Domains the build may reach. Omitted means unrestricted, because a build
   * that installs packages needs the network by definition.
   */
  allowDomains?: string[];
  /**
   * Boot the image's own systemd under the agent instead of the agent alone.
   * Everything created from the template keeps the mode. The image has to
   * ship systemd.
   */
  systemd?: boolean;
  /** Called for every build log line. */
  onBuildLogs?: (log: BuildLogEvent) => void;
}

export type BuildLogEvent =
  | { type: "step"; command: string }
  | { type: "stdout"; data: string }
  | { type: "stderr"; data: string }
  | { type: "done"; template: string; sizeBytes: number };

/** What a finished build reports. */
export interface BuildResult {
  template: string;
  sizeBytes: number;
}

export interface TemplateInfo {
  name: string;
  sizeBytes: number;
  /** True when creates from this template restore a snapshot instead of booting. */
  warm: boolean;
  /** Imported from Sandbox Kits: creates run their lifecycle. */
  kit: boolean;
  /** Sandboxes from it run systemd under the agent. */
  systemd: boolean;
  /** `linux`, `windows` or `macos`. */
  guestOs: string;
  /** The hypervisor every sandbox from this template runs under. */
  hypervisor: string;
}

/** Prints build logs the way a build tool would. */
export function defaultBuildLogger(
  write: (line: string) => void = (line) => process.stdout.write(line),
): (log: BuildLogEvent) => void {
  return (log) => {
    switch (log.type) {
      case "step":
        write(`\n→ ${log.command}\n`);
        break;
      case "stdout":
      case "stderr":
        write(log.data);
        break;
      case "done":
        write(`\n✓ built ${log.template} (${(log.sizeBytes / 1e6).toFixed(1)} MB)\n`);
        break;
    }
  };
}

/**
 * Describes a guest image as a base plus a list of steps.
 *
 * Steps run in a real sandbox and the resulting filesystem becomes the image,
 * so anything a command can do is fair game: there is no separate build
 * language to learn.
 *
 * ```ts
 * const template = Template()
 *   .fromTemplate("default")
 *   .runCmd("apk add --no-cache python3 py3-pip")
 *   .pipInstall(["cowsay", "requests"]);
 *
 * await Template.build(template, "python-tools", {
 *   onBuildLogs: defaultBuildLogger(),
 * });
 * ```
 */
export class TemplateBuilder {
  private base = "default";
  private image = "";
  private ipsw = "";
  private readonly steps: BuildStep[] = [];

  /** Sets the burrow template to start from. Defaults to `"default"`. */
  fromTemplate(name: string): this {
    this.base = name;
    this.image = "";
    this.ipsw = "";
    return this;
  }

  /**
   * Installs macOS from a restore image on a Mac node: a path on that node,
   * or `"latest"`, which the node downloads from Apple and keeps. The
   * template runs under `vz` and takes no steps; build on it with
   * {@link fromTemplate} to add some.
   */
  fromIpsw(source: string): this {
    this.ipsw = source;
    this.image = "";
    return this;
  }

  /**
   * Starts from an OCI image, e.g. `"python:3.12-slim"` or
   * `"ghcr.io/org/tool@sha256:..."`.
   *
   * Its layers become the root filesystem and burrow's agent is installed as
   * init, so the image's environment and working directory carry over but
   * nothing belonging to a container runtime (entrypoint, user, signal
   * handling) does.
   */
  fromImage(reference: string): this {
    this.image = reference;
    this.ipsw = "";
    return this;
  }

  /** Runs a shell command. */
  runCmd(...commands: string[]): this {
    for (const command of commands) {
      if (command.trim()) this.steps.push({ run: command });
    }
    return this;
  }

  /** Installs Python packages with pip. */
  pipInstall(packages: string[] | string): this {
    const list = toList(packages);
    return list.length ? this.runCmd(`pip install --no-cache-dir ${list.join(" ")}`) : this;
  }

  /** Installs Node packages globally, so they are on `PATH` for sandboxes. */
  npmInstall(packages: string[] | string): this {
    const list = toList(packages);
    return list.length ? this.runCmd(`npm install -g ${list.join(" ")}`) : this;
  }

  /** Installs system packages with apt. */
  aptInstall(packages: string[] | string): this {
    const list = toList(packages);
    if (!list.length) return this;
    return this.runCmd(
      `apt-get update && apt-get install -y --no-install-recommends ${list.join(" ")} && rm -rf /var/lib/apt/lists/*`,
    );
  }

  /** Installs system packages with apk (Alpine). */
  apkInstall(packages: string[] | string): this {
    const list = toList(packages);
    return list.length ? this.runCmd(`apk add --no-cache ${list.join(" ")}`) : this;
  }

  /** Writes a file into the image. */
  writeFile(path: string, contents: string): this {
    // Base64 so quotes, newlines and shell metacharacters survive the command.
    const encoded = Buffer.from(contents, "utf8").toString("base64");
    return this.runCmd(
      `mkdir -p "$(dirname ${quote(path)})" && echo ${quote(encoded)} | base64 -d > ${quote(path)}`,
    );
  }

  /** Creates a directory in the image. */
  mkdir(path: string): this {
    return this.runCmd(`mkdir -p ${quote(path)}`);
  }

  /** The steps this template will run, in order. */
  get plan(): ReadonlyArray<BuildStep> {
    return this.steps;
  }

  /** @internal The `BuildTemplateRequest` this builder describes. */
  toRequest(name: string, options: BuildOptions) {
    return {
      name,
      // An OCI base takes the place of a template base; sending both would
      // leave the node to guess which was meant.
      from: this.image || this.ipsw ? "" : this.base,
      fromImage: this.image,
      fromIpsw: this.ipsw,
      steps: this.steps,
      // Zero is the node's default for the guest being built.
      vcpus: options.vcpus ?? 0,
      memMib: options.memoryMib ?? 0,
      allowDomains: options.allowDomains ?? [],
      isSystemd: options.systemd ?? false,
      hypervisor: options.hypervisor ?? "",
      diskMib: options.diskMib ?? 0,
    };
  }
}

/** @internal One `BuildLog` message as a {@link BuildLogEvent}. */
export function toBuildEvent(raw: any): BuildLogEvent | undefined {
  if (raw.step) return { type: "step", command: raw.step };
  if (raw.stdout?.length) {
    return { type: "stdout", data: Buffer.from(raw.stdout).toString("utf8") };
  }
  if (raw.stderr?.length) {
    return { type: "stderr", data: Buffer.from(raw.stderr).toString("utf8") };
  }
  if (raw.done) {
    return {
      type: "done",
      template: raw.done.template,
      sizeBytes: Number(raw.done.sizeBytes ?? 0),
    };
  }
  return undefined;
}

/** @internal One `TemplateInfo` message. */
export function toTemplateInfo(raw: any): TemplateInfo {
  return {
    name: raw.name,
    sizeBytes: Number(raw.sizeBytes ?? 0),
    warm: Boolean(raw.isWarm),
    kit: Boolean(raw.isKit),
    systemd: Boolean(raw.isSystemd),
    guestOs: raw.guestOs ?? "",
    hypervisor: raw.hypervisor ?? "",
  };
}

function toList(packages: string[] | string): string[] {
  return (Array.isArray(packages) ? packages : [packages]).filter(Boolean);
}

function quote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

interface TemplateFactory {
  (): TemplateBuilder;
  /** Builds a template and publishes it under `name`. */
  build(
    template: TemplateBuilder,
    name: string,
    options?: BuildOptions & TransportOptions,
  ): Promise<BuildResult>;
  /** Lists the templates available across the fleet. */
  list(options?: TransportOptions & CallOptions): Promise<TemplateInfo[]>;
  /** Deletes a template. */
  delete(name: string, options?: TransportOptions & CallOptions): Promise<void>;
}

const factory = (() => new TemplateBuilder()) as TemplateFactory;

factory.build = (template, name, options = {}) =>
  withClient(options, (burrow) => burrow.templates.build(template, name, options));

factory.list = (options = {}) =>
  withClient(options, (burrow) => burrow.templates.list(options));

factory.delete = (name, options = {}) =>
  withClient(options, (burrow) => burrow.templates.delete(name, options));

export const Template = factory;
