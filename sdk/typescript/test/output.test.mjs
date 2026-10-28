// What a command's output looks like by the time it reaches the caller: text
// decoded across chunk boundaries, the bytes exactly, and the signal that
// ended it.

import assert from "node:assert/strict";
import { test } from "node:test";

import { Sandbox } from "../dist/index.js";

/** A sandbox whose node answers every exec with `messages`. */
function sandboxPrinting(messages) {
  const node = {
    openStream() {
      const output = (async function* () {
        yield { output: "commandId", commandId: "cmd_1" };
        for (const message of messages) yield message;
      })();
      return { call: { write() {}, end() {}, cancel() {} }, output };
    },
  };
  return Sandbox.adopt(
    { route: () => node },
    { id: "sbx_test", state: "SANDBOX_STATE_RUNNING" },
  );
}

test("a character split across chunks arrives whole", async () => {
  const euro = Buffer.from("€");
  const sandbox = sandboxPrinting([
    { output: "stdout", stdout: Buffer.concat([Buffer.from("price "), euro.subarray(0, 1)]) },
    { output: "stdout", stdout: Buffer.concat([euro.subarray(1), Buffer.from("5")]) },
    { output: "exitCode", exitCode: 0 },
  ]);
  const result = await sandbox.exec("echo");
  assert.equal(result.stdout, "price €5");
  assert.deepEqual(Buffer.from(result.stdoutBytes), Buffer.from("price €5"));
});

test("output that is not text comes back byte for byte", async () => {
  const blob = Buffer.from(Array.from({ length: 256 }, (_, n) => n));
  const sandbox = sandboxPrinting([
    { output: "stdout", stdout: blob },
    { output: "exitCode", exitCode: 0 },
  ]);
  assert.deepEqual(Buffer.from((await sandbox.exec("cat")).stdoutBytes), blob);
});

test("an exit a signal caused names the signal", async () => {
  const sandbox = sandboxPrinting([
    { output: "exitSignal", exitSignal: 15 },
    { output: "exitCode", exitCode: 143 },
  ]);
  const result = await sandbox.exec("sleep 9");
  assert.equal(result.exitCode, 143);
  assert.equal(result.exitSignal, 15);
  assert.equal(result.success, false);
});

test("output the sandbox does not have is reported, by how much", async () => {
  const sandbox = sandboxPrinting([
    { output: "lostBytes", lostBytes: 42 },
    { output: "stdout", stdout: Buffer.from("tail") },
    { output: "exitCode", exitCode: 0 },
  ]);
  const chunks = [];
  for await (const chunk of sandbox.execStream("yes")) chunks.push(chunk);
  assert.deepEqual(chunks[0], { type: "lost", lostBytes: 42 });
  assert.equal(chunks[1].data, "tail");
});
