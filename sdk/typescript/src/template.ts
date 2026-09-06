import { Buffer } from "node:buffer";

import { BurrowError } from "./errors.js";
import { Transport, type TransportOptions } from "./transport.js";

/** One step of a template build. */
export interface BuildStep {
  run: string;
}

export interface BuildOptions extends TransportOptions {
  /** vCPUs given to the build sandbox. */
  cpuCount?: number;
  /** Memory given to the build sandbox, in MiB. */
  memoryMB?: number;
  /**
   * Domains the build may reach. Omitted means unrestricted, because a build
   * that installs packages needs the network by definition.
   */
  allowDomains?: string[];
  /** Called for every build log line. */
  onBuildLogs?: (log: BuildLogEvent) => void;
  /** Milliseconds before the build is abandoned. */
  timeoutMs?: number;
}

export type BuildLogEvent =
  | { type: "step"; command: string }
  | { type: "stdout"; data: string }
  | { type: "stderr"; data: string }
  | { type: "done"; template: string; sizeBytes: number };

export interface TemplateInfo {
  name: string;
  sizeBytes: number;
  /** True when creates from this template restore a snapshot instead of booting. */
  warm: boolean;
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
        write(
          `\n✓ built ${log.template} (${(log.sizeBytes / 1e6).toFixed(1)} MB)\n`,
        );
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
  private readonly steps: BuildStep[] = [];

  /** Sets the burrow template to start from. Defaults to `"default"`. */
  fromTemplate(name: string): this {
    this.base = name;
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
    return list.length
      ? this.runCmd(`pip install --no-cache-dir ${list.join(" ")}`)
      : this;
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
    return list.length
      ? this.runCmd(`apk add --no-cache ${list.join(" ")}`)
      : this;
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

  /**
   * Creates the directory later steps are meant to work in. Steps do not
   * inherit a working directory, so `cd` inside the step that needs it.
   */
  workdir(path: string): this {
    return this.runCmd(`mkdir -p ${quote(path)}`);
  }

  /** @internal */
  toRequest(name: string, options: BuildOptions) {
    return {
      name,
      // An OCI base takes the place of a template base; sending both would
      // leave the node to guess which was meant.
      from: this.image ? "" : this.base,
      fromImage: this.image,
      steps: this.steps,
      vcpus: options.cpuCount ?? 1,
      memMib: options.memoryMB ?? 1024,
      allowDomains: options.allowDomains ?? [],
    };
  }

  /** The steps this template will run, in order. */
  get plan(): ReadonlyArray<BuildStep> {
    return this.steps;
  }
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
    options?: BuildOptions,
  ): Promise<TemplateInfo>;
  /** Lists the templates available across the fleet. */
  list(options?: TransportOptions): Promise<TemplateInfo[]>;
  /** Deletes a template. */
  delete(name: string, options?: TransportOptions): Promise<void>;
}

const factory = (() => new TemplateBuilder()) as TemplateFactory;

factory.build = async function build(
  template: TemplateBuilder,
  name: string,
  options: BuildOptions = {},
): Promise<TemplateInfo> {
  const transport = new Transport(options);
  try {
    let result: TemplateInfo | undefined;
    for await (const raw of transport.serverStream<any, any>(
      "BuildTemplate",
      template.toRequest(name, options),
      // Builds install packages; minutes, not seconds.
      options.timeoutMs ?? 30 * 60_000,
    )) {
      const event = toEvent(raw);
      if (!event) continue;
      options.onBuildLogs?.(event);
      if (event.type === "done") {
        result = {
          name: event.template,
          sizeBytes: event.sizeBytes,
          // A freshly built template has no snapshot until the node warms it.
          warm: false,
        };
      }
    }
    if (!result) {
      throw new BurrowError("build ended without producing an image", "internal");
    }
    return result;
  } finally {
    transport.close();
  }
};

factory.list = async function list(
  options: TransportOptions = {},
): Promise<TemplateInfo[]> {
  const transport = new Transport(options);
  try {
    const res = await transport.unary<any, any>("ListTemplates", {});
    return (res.templates ?? []).map((t: any) => ({
      name: t.name,
      sizeBytes: Number(t.sizeBytes ?? 0),
      warm: Boolean(t.warm),
    }));
  } finally {
    transport.close();
  }
};

factory.delete = async function remove(
  name: string,
  options: TransportOptions = {},
): Promise<void> {
  const transport = new Transport(options);
  try {
    await transport.unary("DeleteTemplate", { name });
  } finally {
    transport.close();
  }
};

function toEvent(raw: any): BuildLogEvent | undefined {
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

export const Template = factory;
