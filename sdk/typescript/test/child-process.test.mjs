// `sandbox.childProcess` is `child_process`: argv built the way Node builds
// it, the events Node emits in the order it emits them, and the same error
// from a failed `exec`.

import assert from "node:assert/strict";
import { once } from "node:events";
import { test } from "node:test";

import { Sandbox } from "../dist/index.js";

/** A stream of `ExecOutput` messages the test feeds as it goes. */
function feed() {
  const queue = [];
  let wake;
  let done = false;
  return {
    push(...messages) {
      queue.push(...messages);
      wake?.();
    },
    end() {
      done = true;
      wake?.();
    },
    output: (async function* () {
      while (true) {
        while (queue.length) yield queue.shift();
        if (done) return;
        await new Promise((resolve) => (wake = resolve));
      }
    })(),
  };
}

/**
 * A sandbox whose node opens one exec per `spawn` and records what it was
 * sent. Each exec's output is handed to `script`, which drives it.
 */
function execSandbox(script = () => {}) {
  const execs = [];
  const unary = [];
  const node = {
    openStream(method, first) {
      const stream = feed();
      const exec = { method, start: first.start, writes: [], ended: false, stream };
      execs.push(exec);
      script(stream, exec);
      return {
        call: {
          write: (message) => exec.writes.push(message),
          end: () => (exec.ended = true),
          cancel() {},
        },
        output: stream.output,
      };
    },
  };
  const transport = {
    route: () => node,
    async unary(method, request) {
      unary.push({ method, request });
      return {};
    },
  };
  const sandbox = Sandbox.adopt(transport, { id: "sbx_test", state: "SANDBOX_STATE_RUNNING" });
  return { sandbox, execs, unary };
}

/** A script that runs to completion: id, the messages given, then the stream ends. */
const runs = (...messages) => (stream) => {
  stream.push({ output: "commandId", commandId: "cmd_1" }, ...messages);
  stream.end();
};

test("without a shell the command is the program, with no shell involved", () => {
  const { sandbox, execs } = execSandbox();
  sandbox.childProcess.spawn("echo", ["a b", "$HOME"]);
  assert.deepEqual(execs[0].start.cmd, ["echo", "a b", "$HOME"]);
});

test("with a shell the words are joined and run by it, as Node does", () => {
  const { sandbox, execs } = execSandbox();
  const child = sandbox.childProcess.spawn("ls", ["-l", "/work"], { shell: true });
  sandbox.childProcess.spawn("echo $HOME", { shell: "/bin/bash" });
  assert.deepEqual(execs[0].start.cmd, ["/bin/sh", "-c", "ls -l /work"]);
  assert.deepEqual(execs[1].start.cmd, ["/bin/bash", "-c", "echo $HOME"]);
  assert.equal(child.spawnfile, "/bin/sh");
  assert.deepEqual(child.spawnargs, ["/bin/sh", "-c", "ls -l /work"]);
});

test("exec goes through a shell and execFile does not", async () => {
  const { sandbox, execs } = execSandbox(runs({ output: "exitCode", exitCode: 0 }));
  await sandbox.childProcess.exec("ls | wc -l");
  await sandbox.childProcess.execFile("python3", ["-c", "print(1)"]);
  assert.deepEqual(execs[0].start.cmd, ["/bin/sh", "-c", "ls | wc -l"]);
  assert.deepEqual(execs[1].start.cmd, ["python3", "-c", "print(1)"]);
});

test("a command a signal ended exits with a null code and the signal's name", async () => {
  const { sandbox } = execSandbox(
    runs(
      { output: "stdout", stdout: Buffer.from("hi") },
      { output: "exitSignal", exitSignal: 15 },
      { output: "exitCode", exitCode: 143 },
    ),
  );
  const child = sandbox.childProcess.spawn("sleep", ["9"]);
  assert.equal(child.pid, undefined);
  const events = [];
  let stdout = "";
  child.on("spawn", () => events.push(["spawn", child.cmdId]));
  child.on("exit", (code, signal) => events.push(["exit", code, signal]));
  // As with Node, output may still be arriving when `exit` fires; by
  // `close` it has all arrived.
  child.stdout.on("data", (chunk) => (stdout += chunk));

  const [code, signal] = await once(child, "close");
  assert.deepEqual([code, signal], [null, "SIGTERM"]);
  assert.equal(stdout, "hi");
  assert.deepEqual(events, [
    ["spawn", "cmd_1"],
    ["exit", null, "SIGTERM"],
  ]);
  assert.equal(child.exitCode, null);
  assert.equal(child.signalCode, "SIGTERM");
});

test("an ordinary exit reports its code and no signal", async () => {
  const { sandbox } = execSandbox(runs({ output: "exitCode", exitCode: 3 }));
  const child = sandbox.childProcess.spawn("false");
  const exit = once(child, "exit");
  const close = once(child, "close");
  assert.deepEqual(await exit, [3, null]);
  // Nobody read stdout, and close still comes: unread output is drained.
  assert.deepEqual(await close, [3, null]);
  assert.equal(child.exitCode, 3);
});

test("stdin waits for the command, then reaches the exec stream", async () => {
  let stream;
  const { sandbox, execs } = execSandbox((s) => (stream = s));
  const child = sandbox.childProcess.spawn("cat");
  child.stdin.write("hello ");
  child.stdin.end("world");
  await new Promise((resolve) => setImmediate(resolve));
  // Nothing goes before the guest has named the command.
  assert.deepEqual(execs[0].writes, []);

  stream.push({ output: "commandId", commandId: "cmd_1" });
  await once(child, "spawn");
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(execs[0].writes, [
    { stdin: Buffer.from("hello ") },
    { stdin: Buffer.from("world") },
    { isStdinEof: true },
  ]);
  stream.push({ output: "exitCode", exitCode: 0 });
  stream.end();
  await once(child, "close");
  assert.equal(execs[0].ended, true);
});

test("an ignored stdin is closed at once and is null", () => {
  const { sandbox, execs } = execSandbox();
  const child = sandbox.childProcess.spawn("true", [], { stdio: ["ignore", "pipe", "pipe"] });
  assert.equal(child.stdin, null);
  assert.deepEqual(execs[0].writes, [{ isStdinEof: true }]);
});

test("kill sends SIGTERM by its Linux number and reports false once exited", async () => {
  let stream;
  const { sandbox, unary } = execSandbox((s) => {
    stream = s;
    s.push({ output: "commandId", commandId: "cmd_1" });
  });
  const child = sandbox.childProcess.spawn("sleep", ["60"]);
  await once(child, "spawn");
  assert.equal(child.kill(), true);
  assert.equal(child.killed, true);
  child.kill("SIGUSR1");
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(
    unary.map(({ method, request }) => [method, request.commandId, request.signal]),
    [
      ["SignalCommand", "cmd_1", 15],
      ["SignalCommand", "cmd_1", 10],
    ],
  );
  assert.throws(() => child.kill("SIGNOPE"), { code: "ERR_UNKNOWN_SIGNAL" });

  stream.push({ output: "exitSignal", exitSignal: 15 }, { output: "exitCode", exitCode: 143 });
  stream.end();
  await once(child, "exit");
  assert.equal(child.kill(), false);
});

test("exec resolves stdout and stderr, decoded across chunk boundaries", async () => {
  const euro = Buffer.from("€");
  const { sandbox } = execSandbox(
    runs(
      { output: "stdout", stdout: Buffer.concat([Buffer.from("price "), euro.subarray(0, 1)]) },
      { output: "stdout", stdout: Buffer.concat([euro.subarray(1), Buffer.from("5")]) },
      { output: "stderr", stderr: Buffer.from("warn") },
      { output: "exitCode", exitCode: 0 },
    ),
  );
  assert.deepEqual(await sandbox.childProcess.exec("echo"), { stdout: "price €5", stderr: "warn" });
  const raw = await sandbox.childProcess.exec("echo", { encoding: "buffer" });
  assert.deepEqual(raw.stdout, Buffer.from("price €5"));
});

test("a failed exec rejects with Node's error", async () => {
  const { sandbox } = execSandbox(
    runs(
      { output: "stdout", stdout: Buffer.from("partial") },
      { output: "stderr", stderr: Buffer.from("boom\n") },
      { output: "exitCode", exitCode: 2 },
    ),
  );
  const promise = sandbox.childProcess.exec("make all");
  assert.ok(promise.child);
  await assert.rejects(promise, (err) => {
    assert.ok(err instanceof Error);
    assert.equal(err.message, "Command failed: make all\nboom\n");
    assert.equal(err.code, 2);
    assert.equal(err.signal, null);
    assert.equal(err.killed, false);
    assert.equal(err.cmd, "make all");
    assert.equal(err.stdout, "partial");
    assert.equal(err.stderr, "boom\n");
    return true;
  });
});

test("an exec a signal ended rejects with a null code and the signal", async () => {
  const { sandbox } = execSandbox(
    runs({ output: "exitSignal", exitSignal: 9 }, { output: "exitCode", exitCode: 137 }),
  );
  await assert.rejects(sandbox.childProcess.execFile("sleep", ["9"]), {
    code: null,
    signal: "SIGKILL",
    cmd: "sleep 9",
  });
});

test("the handle's env and user go under the command's own", () => {
  const { sandbox, execs } = execSandbox();
  sandbox.asUser("alice").childProcess.spawn("env", { env: { STAGE: "x", DROP: undefined }, cwd: "/work" });
  assert.equal(execs[0].start.user, "alice");
  assert.deepEqual(execs[0].start.env, { STAGE: "x" });
  assert.equal(execs[0].start.cwd, "/work");
});

test("output a rotated log dropped is reported, by how much", async () => {
  const { sandbox } = execSandbox(
    runs({ output: "lostBytes", lostBytes: 42 }, { output: "exitCode", exitCode: 0 }),
  );
  const child = sandbox.childProcess.spawn("yes");
  assert.deepEqual(await once(child, "lost"), [42]);
});
