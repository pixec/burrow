// End-to-end tour of the SDK. Needs a running burrow stack:
//   docker --context colima-burrow compose -f deploy/dev/compose.yaml up -d
//
//   node examples/quickstart.mjs
import { once } from "node:events";
import { createWriteStream } from "node:fs";
import { mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { pipeline } from "node:stream/promises";

import { Sandbox } from "../dist/index.js";

// getOrCreate keys on the sandbox's name, so running this twice reuses the
// first one. No network unless asked for: this one needs pypi, and nothing else.
const sandbox = await Sandbox.getOrCreate({
  name: `quickstart-${(process.env.USER ?? "local").toLowerCase()}`,
  // A create must name a template; burrow ships none of its own. Import this
  // one with: burrow pull python:3.12 --name python
  template: "python",
  networkPolicy: {
    mode: "allowlist",
    allowDomains: ["pypi.org", "*.pythonhosted.org"],
    denyCidrs: ["169.254.0.0/16"],
  },
  resources: { vcpus: 1, memoryMib: 512, idleSuspendSecs: 300, suspendedTtlSecs: 3600 },
  tags: { purpose: "quickstart", owner: "sdk-example" },
  // Merged under every command this handle runs.
  env: { QUICKSTART: "1" },
  onCreate: (s) => console.log("created:", s.id),
  onResume: (s) => console.log("resumed:", s.name),
});
console.log("sandbox:", sandbox.name, sandbox.id, sandbox.state, `${sandbox.vcpus} vcpu`, `${sandbox.memoryMib} MiB`);

// The same calls as node:child_process and node:fs/promises, run in the guest.
const { exec, execFile, spawn } = sandbox.childProcess;
const fs = sandbox.fs;

try {
  // execFile runs the program directly: no shell, so nothing needs quoting.
  const hello = await execFile("echo", ["hello from the sandbox"]);
  console.log("execFile:", hello.stdout.trim());

  // exec goes through /bin/sh, so pipes and redirection work.
  const piped = await exec("echo one two three | tr ' ' '\\n' | wc -l");
  console.log("shell:", piped.stdout.trim());

  // Options carry cwd and env.
  const where = await exec("pwd; echo $QUICKSTART $STAGE", {
    cwd: "/work",
    env: { STAGE: "tour" },
  });
  console.log("cwd and env:", where.stdout.trim().split("\n").join(" | "));

  // spawn hands back a ChildProcess: streams and events, as Node's.
  const job = spawn("sh", ["-c", "for i in 1 2 3; do echo tick $i; done"]);
  job.stdout.on("data", (chunk) => process.stdout.write(`  ${chunk}`));
  console.log("job closed:", await once(job, "close"));

  // Signals by name; a command a signal ended has a null exit code.
  const sleeper = spawn("sleep", ["60"]);
  await once(sleeper, "spawn");
  sleeper.kill("SIGTERM");
  console.log("killed:", await once(sleeper, "exit"));

  // stdin is a Writable that reaches the command.
  const cat = spawn("cat");
  cat.stdin.end("piped through cat\n");
  cat.stdout.on("data", (chunk) => process.stdout.write(`  ${chunk}`));
  await once(cat, "close");

  // Files, as fs/promises.
  await fs.mkdir("/work", { recursive: true });
  await fs.writeFile("/work/hello.sh", "echo written from the SDK\n");
  await fs.writeFile("/work/run.sh", "sh /work/hello.sh\n", { mode: 0o755 });
  const script = await execFile("sh", ["/work/run.sh"]);
  console.log("file:", script.stdout.trim());
  console.log("dir:", (await fs.readdir("/work")).join(", "));
  const stats = await fs.stat("/work/run.sh");
  console.log("run.sh:", stats.size, "bytes, mode", (stats.mode & 0o777).toString(8));

  // Errors are Node's, code and all.
  try {
    await fs.readFile("/work/nope.txt");
  } catch (err) {
    console.log("missing file:", err.code, err.message);
  }

  // Copy one back out to the local filesystem through a FileHandle stream.
  const local = `${tmpdir()}/burrow-quickstart/hello.sh`;
  await mkdir(`${tmpdir()}/burrow-quickstart`, { recursive: true });
  const handle = await fs.open("/work/hello.sh");
  await pipeline(handle.createReadStream(), createWriteStream(local));
  console.log("downloaded to:", local);

  // Denied hosts fail rather than silently succeeding.
  const blocked = await exec("wget -qO- http://example.com/").catch((err) => err);
  console.log("example.com reachable:", !(blocked instanceof Error));

  // Tighten the policy on a running sandbox.
  await sandbox.updateTags({ purpose: "quickstart", stage: "locked-down" });
  await sandbox.updateNetworkPolicy("none");
  console.log("tags now:", JSON.stringify(sandbox.tags));

  // A failed command rejects with Node's error.
  try {
    await exec("exit 3");
  } catch (err) {
    console.log("caught exit:", err.code);
  }

  // Fork clones the sandbox's current state into a new one; the source's state
  // is written first, so the child starts from what it looks like right now.
  const child = await sandbox.fork({ name: `${sandbox.name}-fork` });
  try {
    console.log("fork:", child.name, child.id);
    console.log("fork sees the file:", (await child.fs.readFile("/work/hello.sh", "utf8")).trim());
  } finally {
    await child.delete();
  }

  // stop suspends; resume brings it back.
  await sandbox.stop();
  const started = Date.now();
  await sandbox.resume();
  console.log("resumed in:", `${Date.now() - started}ms`);
  console.log("file survived:", (await fs.readFile("/work/hello.sh", "utf8")).trim());

  // Auto-resume: a call on a suspended sandbox resumes it and retries once.
  await sandbox.stop();
  const revived = await execFile("cat", ["/work/hello.sh"]);
  console.log("auto-resumed:", revived.stdout.trim());
} finally {
  await sandbox.delete();
}
