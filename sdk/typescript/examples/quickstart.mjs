// End-to-end tour of the SDK. Needs a running burrow stack:
//   docker --context colima-burrow compose -f deploy/docker/compose.yaml up -d
//
//   node examples/quickstart.mjs
import { tmpdir } from "node:os";

import { Sandbox, CommandFailedError } from "../dist/index.js";

// getOrCreate keys on the sandbox's name, so running this twice reuses the
// first one. No network unless asked for: this one needs pypi, and nothing else.
const sandbox = await Sandbox.getOrCreate({
  name: `quickstart-${(process.env.USER ?? "local").toLowerCase()}`,
  // A create must name a template; burrow ships none of its own. Import this
  // one with: burrow pull python:3.12 --name python
  template: "python",
  // The shorthand policy shape. `subnets` maps to allowed and denied ranges.
  networkPolicy: {
    allow: ["pypi.org", "*.pythonhosted.org"],
    subnets: { deny: ["169.254.0.0/16"] },
  },
  resources: { vcpus: 1, memoryMib: 512, idleSuspendSecs: 300, suspendedTtlSecs: 3600 },
  tags: { purpose: "quickstart", owner: "sdk-example" },
  // Merged under every command this handle runs.
  env: { QUICKSTART: "1" },
  onCreate: (s) => console.log("created:", s.id),
  onResume: (s) => console.log("resumed:", s.name),
});
console.log("sandbox:", sandbox.name, sandbox.id, sandbox.status, `${sandbox.vcpus} vcpu`, `${sandbox.memory} MiB`);

try {
  // runCommand runs to completion. stdout and stderr are methods.
  const hello = await sandbox.runCommand("echo", ["hello from the sandbox"]);
  console.log("run:", hello.exitCode, hello.stdout().trim());

  // A bare string goes through a shell, so pipes and redirection work.
  const piped = await sandbox.runCommand("echo one two three | tr ' ' '\\n' | wc -l");
  console.log("shell:", piped.stdout().trim());

  // The object form carries cwd, env, and streams to pipe output into.
  const where = await sandbox.runCommand({
    cmd: "sh",
    args: ["-c", "pwd; echo $QUICKSTART $STAGE"],
    cwd: "/work",
    env: { STAGE: "tour" },
  });
  console.log("cwd and env:", where.stdout().trim().split("\n").join(" | "));

  // Detached hands back a handle you can stream from, wait on, or kill.
  const job = await sandbox.runCommand({ cmd: "sh", args: ["-c", "for i in 1 2 3; do echo tick $i; done"], detached: true });
  for await (const chunk of job.logs()) {
    if (chunk.type === "stdout") process.stdout.write(`  ${chunk.data}`);
  }

  const sleeper = await sandbox.runCommand({ cmd: "sleep", args: ["60"], detached: true });
  sleeper.kill();
  console.log("killed:", (await sleeper.wait()).exitCode);

  // Write several files in one call.
  await sandbox.writeFiles([
    { path: "/work/hello.sh", content: "echo written from the SDK\n" },
    { path: "/work/run.sh", content: "sh /work/hello.sh\n", mode: 0o755 },
  ]);
  const script = await sandbox.runCommand("sh", ["/work/run.sh"]);
  console.log("file:", script.stdout().trim());
  console.log("dir:", (await sandbox.listDir("/work")).map((e) => e.name).join(", "));

  // Copy one back out to the local filesystem.
  const copied = await sandbox.downloadFile(
    "/work/hello.sh",
    `${tmpdir()}/burrow-quickstart/hello.sh`,
  );
  console.log("downloaded to:", copied);

  // Denied hosts fail rather than silently succeeding.
  const blocked = await sandbox.runCommand("wget -qO- http://example.com/");
  console.log("example.com reachable:", blocked.exitCode === 0);

  // Tighten the policy on a running sandbox. Tags and network in one call.
  await sandbox.update({
    tags: { purpose: "quickstart", stage: "locked-down" },
    networkPolicy: "deny-all",
  });
  console.log("tags now:", JSON.stringify(sandbox.tags));

  try {
    await sandbox.exec("exit 3", { check: true });
  } catch (err) {
    if (err instanceof CommandFailedError) console.log("caught exit:", err.exitCode);
  }

  // Fork clones the sandbox's current state into a new one; the source's state
  // is written first, so the child starts from what it looks like right now.
  const child = await sandbox.fork({ name: `${sandbox.name}-fork` });
  try {
    console.log("fork:", child.name, child.id);
    console.log(
      "fork sees the file:",
      (await child.readFile("/work/hello.sh")).trim(),
    );
  } finally {
    await child.delete();
  }

  // stop suspends; resume brings it back.
  await sandbox.stop();
  const started = Date.now();
  await sandbox.resume();
  console.log("resumed in:", `${Date.now() - started}ms`);
  console.log("file survived:", (await sandbox.readFile("/work/hello.sh")).trim());

  // Auto-resume: a call on a suspended sandbox resumes it and retries once.
  await sandbox.stop();
  const revived = await sandbox.runCommand("cat", ["/work/hello.sh"]);
  console.log("auto-resumed:", revived.stdout().trim());
} finally {
  await sandbox.delete();
}
