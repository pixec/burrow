// The class-level helpers open a connection of their own: `callTimeoutMs` is
// that connection's default, and `timeoutMs` reaches the call they make.

import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { Sandbox, Template } from "../dist/index.js";
import { Transport } from "../dist/transport.js";

const { unary, serverStream } = Transport.prototype;
afterEach(() => Object.assign(Transport.prototype, { unary, serverStream }));

function record() {
  const calls = [];
  Transport.prototype.unary = async function (method, request, timeoutMs) {
    calls.push({ method, timeoutMs, defaultMs: this.timeoutMs });
    return { id: "sbx_test" };
  };
  Transport.prototype.serverStream = async function* (method, request, timeoutMs) {
    calls.push({ method, timeoutMs, defaultMs: this.timeoutMs });
    yield { done: { template: "t", sizeBytes: "0" } };
  };
  return calls;
}

test("create waits past the connection default", async () => {
  const calls = record();
  const sandbox = await Sandbox.create({
    endpoint: "localhost:1",
    template: "python",
    timeoutMs: 600_000,
    callTimeoutMs: 5_000,
  });
  sandbox.close();
  assert.deepEqual(calls, [{ method: "CreateSandbox", timeoutMs: 600_000, defaultMs: 5_000 }]);
});

test("create waits two minutes by default", async () => {
  const calls = record();
  const sandbox = await Sandbox.create({ endpoint: "localhost:1", template: "python" });
  sandbox.close();
  assert.deepEqual(calls, [{ method: "CreateSandbox", timeoutMs: 120_000, defaultMs: 60_000 }]);
});

test("build takes its own deadline", async () => {
  const calls = record();
  await Template.build(Template().fromImage("python:3.12"), "t", {
    endpoint: "localhost:1",
    timeoutMs: 3_600_000,
    callTimeoutMs: 5_000,
  });
  assert.deepEqual(calls, [{ method: "BuildTemplate", timeoutMs: 3_600_000, defaultMs: 5_000 }]);
});

test("a build without a base is refused before anything is sent", async () => {
  const calls = record();
  await assert.rejects(
    Template.build(Template().runCmd("true"), "t", { endpoint: "localhost:1" }),
    (err) => err.code === "invalid_argument" && /needs a base/.test(err.message),
  );
  assert.deepEqual(calls, []);
});
