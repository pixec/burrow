// What `kill()` may swallow, and what it may not.
//
// A sandbox tightened to deny exec refuses signals too, since they go through
// the same door. A `kill()` that hid that would be indistinguishable from one
// that worked, so a refusal surfaces as the child's `error`, as a signal Node
// could not deliver does.

import assert from "node:assert/strict";
import { once } from "node:events";
import { test } from "node:test";

import { BurrowError, Sandbox } from "../dist/index.js";

/**
 * A sandbox whose command `cmd_1` is running and stays that way, and whose
 * `SignalCommand` answers with `outcome`.
 */
function sandboxSignalling(outcome) {
  const signals = [];
  const node = {
    openStream(method, first) {
      assert.equal(method, "Attach");
      assert.deepEqual(first, {
        start: { sandboxId: "sbx_test", commandId: "cmd_1", fromOffset: 0 },
      });
      // Never ends: the command is still running.
      const output = (async function* () {
        await new Promise(() => {});
      })();
      return { call: { write() {}, end() {}, cancel() {} }, output };
    },
  };
  const transport = {
    route: () => node,
    async unary(method, request) {
      if (method === "GetCommand") {
        return { commandId: request.commandId, cmd: ["sleep", "600"] };
      }
      if (method === "SignalCommand") {
        signals.push(request.signal);
        if (outcome) throw outcome;
        return {};
      }
      throw new Error(`unexpected call to ${method}`);
    },
  };
  const sandbox = Sandbox.adopt(transport, { id: "sbx_test", state: "SANDBOX_STATE_RUNNING" });
  return { sandbox, signals };
}

/** Lets every pending callback run. */
const settle = () => new Promise((resolve) => setImmediate(resolve));

test("a command reached by id is a ChildProcess on it", async () => {
  const { sandbox } = sandboxSignalling();
  const child = await sandbox.getCommand("cmd_1");
  assert.equal(child.cmdId, "cmd_1");
  assert.deepEqual(child.spawnargs, ["sleep", "600"]);
  await once(child, "spawn");
});

test("a permission denial is the child's error", async () => {
  const denied = new BurrowError("this sandbox's policy does not allow exec", "permission_denied");
  const child = await sandboxSignalling(denied).sandbox.getCommand("cmd_1");
  assert.equal(child.kill("SIGKILL"), true);
  const [err] = await once(child, "error");
  assert.equal(err.code, "permission_denied");
  assert.match(err.message, /does not allow exec/);
});

test("a command that had already exited is what kill() wanted", async () => {
  const gone = new BurrowError("command cmd_1 has already exited", "failed_precondition");
  const child = await sandboxSignalling(gone).sandbox.getCommand("cmd_1");
  let failed = false;
  child.on("error", () => (failed = true));
  child.kill();
  await settle();
  assert.equal(failed, false);
});

// A suspended sandbox answers with the same code, and it is a real failure to
// deliver: nothing is running to receive the signal.
test("a suspended sandbox is not mistaken for a finished command", async () => {
  const suspended = new BurrowError(
    "sandbox sbx_test is suspended; resume it first",
    "failed_precondition",
  );
  const child = await sandboxSignalling(suspended).sandbox.getCommand("cmd_1");
  child.kill();
  const [err] = await once(child, "error");
  assert.match(err.message, /suspended/);
});

test("a delivered signal goes by its Linux number, and 0 sends nothing", async () => {
  const { sandbox, signals } = sandboxSignalling();
  const child = await sandbox.getCommand("cmd_1");
  assert.equal(child.kill(0), true);
  child.kill("SIGINT");
  child.kill(15);
  await settle();
  assert.deepEqual(signals, [2, 15]);
});
