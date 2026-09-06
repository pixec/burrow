// What `kill()` may swallow, and what it may not.
//
// A sandbox tightened to deny exec refuses signals too, since they go through
// the same door. A `kill()` that hid that would be indistinguishable from one
// that worked.

import assert from "node:assert/strict";
import { test } from "node:test";

import { BurrowError, Sandbox } from "../dist/index.js";

/** A transport that answers `GetCommand` and fails `SignalCommand`. */
function transportRefusing(error) {
  return {
    async unary(method, request) {
      if (method === "GetCommand") {
        return { commandId: request.commandId, cmd: ["sleep", "600"] };
      }
      if (method === "SignalCommand") throw error;
      throw new Error(`unexpected call to ${method}`);
    },
  };
}

function sandboxRefusing(error) {
  return Sandbox.adopt(transportRefusing(error), {
    id: "sbx_test",
    state: "SANDBOX_STATE_RUNNING",
  });
}

/**
 * Collects whatever `kill()` lets escape into the unhandled-rejection path.
 *
 * The channel is taken over for the duration: the test runner installs its own
 * handler there and fails the test on anything it sees, which is exactly the
 * behaviour being asserted rather than a fault.
 */
async function unhandled(body) {
  const escaped = [];
  const previous = process.listeners("unhandledRejection");
  process.removeAllListeners("unhandledRejection");
  const listener = (err) => escaped.push(err);
  process.on("unhandledRejection", listener);
  try {
    await body();
    // A rejection is reported a turn after it is abandoned.
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
  } finally {
    process.off("unhandledRejection", listener);
    for (const handler of previous) process.on("unhandledRejection", handler);
  }
  return escaped;
}

test("a permission denial is observable through killed()", async () => {
  const denied = new BurrowError(
    "this sandbox's policy does not allow exec",
    "permission_denied",
  );
  const sandbox = sandboxRefusing(denied);
  const command = await sandbox.getCommand("cmd_1");

  await assert.rejects(
    () => command.killed(9),
    (err) => {
      assert.equal(err.code, "permission_denied");
      assert.match(err.message, /does not allow exec/);
      return true;
    },
  );
});

// A denial must not be swallowed the way an already-exited command is.
test("a permission denial does not vanish into kill()", async () => {
  const denied = new BurrowError("denied", "permission_denied");
  const sandbox = sandboxRefusing(denied);
  const command = await sandbox.getCommand("cmd_1");

  const escaped = await unhandled(async () => command.kill(9));
  assert.equal(escaped.length, 1, "the denial was swallowed");
  assert.equal(escaped[0].code, "permission_denied");
});

test("a command that had already exited is swallowed by kill()", async () => {
  const gone = new BurrowError(
    "command cmd_1 has already exited",
    "failed_precondition",
  );
  const sandbox = sandboxRefusing(gone);
  const command = await sandbox.getCommand("cmd_1");

  const escaped = await unhandled(async () => command.kill(9));
  assert.deepEqual(escaped, [], "an already-exited command is what kill wanted");

  // It is still visible to a caller who asked to see it.
  await assert.rejects(() => command.killed(9), /already exited/);
});

// A suspended sandbox answers with the same code, and it is a real failure to
// deliver: nothing is running to receive the signal.
test("a suspended sandbox is not mistaken for a finished command", async () => {
  const suspended = new BurrowError(
    "sandbox sbx_test is suspended; resume it first",
    "failed_precondition",
  );
  const sandbox = sandboxRefusing(suspended);
  const command = await sandbox.getCommand("cmd_1");

  const escaped = await unhandled(async () => command.kill(9));
  assert.equal(escaped.length, 1, "a suspended sandbox was swallowed");
  assert.match(escaped[0].message, /suspended/);
});

test("an unknown command id is not swallowed either", async () => {
  const missing = new BurrowError("no such command: cmd_1", "not_found");
  const sandbox = sandboxRefusing(missing);
  const command = await sandbox.getCommand("cmd_1");

  const escaped = await unhandled(async () => command.kill(9));
  assert.equal(escaped.length, 1);
  assert.equal(escaped[0].code, "not_found");
});

test("a delivered signal resolves and is quiet", async () => {
  const transport = {
    async unary(method, request) {
      if (method === "GetCommand") return { commandId: request.commandId };
      return {};
    },
  };
  const sandbox = Sandbox.adopt(transport, {
    id: "sbx_test",
    state: "SANDBOX_STATE_RUNNING",
  });
  const command = await sandbox.getCommand("cmd_1");

  await command.killed(15);
  const escaped = await unhandled(async () => command.kill());
  assert.deepEqual(escaped, []);
});
