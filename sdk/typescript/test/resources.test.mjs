// Reshaping a sandbox and moving its clocks, as the calls go out and their
// answers come back.

import assert from "node:assert/strict";
import { test } from "node:test";

import { BurrowError } from "../dist/index.js";
import { fakeSandbox } from "./helpers.mjs";

function sandboxAnswering(answer) {
  const calls = [];
  const transport = {
    async unary(method, request, timeoutMs) {
      calls.push({ method, request, timeoutMs });
      return answer;
    },
  };
  const sandbox = fakeSandbox(transport, { state: "SANDBOX_STATE_STOPPED" });
  return { sandbox, calls };
}

test("a resources update names its fields and reads back each outcome", async () => {
  const { sandbox, calls } = sandboxAnswering({
    sandbox: {
      id: "sbx_test",
      state: "SANDBOX_STATE_STOPPED",
      policy: { resources: { vcpus: 2, diskMib: 1024 } },
    },
    vcpus: { change: "RESOURCE_CHANGE_NEXT_BOOT", previous: 1, value: 2 },
    memMib: { change: "RESOURCE_CHANGE_REFUSED", previous: 512, value: 512, reason: "suspended" },
    diskMib: { change: "RESOURCE_CHANGE_OFFLINE", previous: 2048, value: 1024 },
    filesystemBytes: "1073741824",
  });
  const updated = await sandbox.updateResources({ vcpus: 2, memoryMib: 1024, diskMib: 1024 });
  assert.equal(calls[0].method, "UpdateResources");
  assert.deepEqual(calls[0].request, {
    sandboxId: "sbx_test",
    vcpus: 2,
    memMib: 1024,
    diskMib: 1024,
  });
  assert.equal(calls[0].timeoutMs, 600_000);
  assert.deepEqual(updated, {
    vcpus: { change: "next_boot", previous: 1, value: 2, reason: "" },
    memoryMib: { change: "refused", previous: 512, value: 512, reason: "suspended" },
    diskMib: { change: "offline", previous: 2048, value: 1024, reason: "" },
    filesystemBytes: 1073741824,
  });
  assert.equal(sandbox.policy.resources.diskMib, 1024);
});

test("a field not asked for has no outcome", async () => {
  const { sandbox } = sandboxAnswering({
    diskMib: { change: "RESOURCE_CHANGE_LIVE", previous: 1024, value: 2048 },
  });
  const updated = await sandbox.updateResources({ diskMib: 2048 });
  assert.equal(updated.diskMib.change, "live");
  assert.equal(updated.vcpus, undefined);
});

test("a value that is not a positive integer is refused before the call", async () => {
  const { sandbox, calls } = sandboxAnswering({});
  for (const bad of [{ diskMib: 0 }, { vcpus: -1 }, { memoryMib: 1.5 }]) {
    await assert.rejects(sandbox.updateResources(bad), BurrowError);
  }
  assert.equal(calls.length, 0);
});

test("a lifetime update sends only what it was given", async () => {
  const { sandbox, calls } = sandboxAnswering({ id: "sbx_test", state: "SANDBOX_STATE_RUNNING" });
  await sandbox.updateLifetime({ maxLifetimeSecs: 7200, snapshots: { keepLast: 2 } });
  assert.equal(calls[0].method, "UpdateLifetime");
  assert.equal(calls[0].request.maxLifetimeSecs, 7200);
  assert.equal(calls[0].request.snapshotKeepLast, 2);
  assert.equal(calls[0].request.idleSuspendSecs, undefined);
  assert.equal(calls[0].request.snapshotExpirationSecs, undefined);
});
