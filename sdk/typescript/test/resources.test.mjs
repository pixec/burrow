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
    cpus: undefined,
    reservedCpus: undefined,
    cpuShares: undefined,
    cpusetCpus: undefined,
    blkioWeight: undefined,
    boot: undefined,
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

test("host limits go out with Docker's names and come back as one outcome", async () => {
  const { sandbox, calls } = sandboxAnswering({
    sandbox: {
      id: "sbx_test",
      state: "SANDBOX_STATE_RUNNING",
      policy: {
        resources: { vcpus: 2, cpus: 0.5, cpuShares: 512, cpusetCpus: "0-1", blkioWeight: 500 },
      },
    },
    limits: { change: "RESOURCE_CHANGE_LIVE" },
  });
  const updated = await sandbox.updateResources({
    cpus: 0.5,
    cpuShares: 512,
    cpusetCpus: "0-1",
    blkioWeight: 500,
  });
  assert.equal(calls[0].request.cpus, 0.5);
  assert.equal(calls[0].request.cpuShares, 512);
  assert.equal(calls[0].request.cpusetCpus, "0-1");
  assert.equal(calls[0].request.blkioWeight, 500);
  assert.deepEqual(updated.limits, { change: "live", reason: "" });
  assert.equal(updated.vcpus, undefined);
  const resources = sandbox.policy.resources;
  assert.equal(resources.cpus, 0.5);
  assert.equal(resources.cpuShares, 512);
  assert.equal(resources.cpusetCpus, "0-1");
  assert.equal(resources.blkioWeight, 500);
});

test("memory grows live, and a shrink says where it stopped", async () => {
  const { sandbox } = sandboxAnswering({
    sandbox: {
      id: "sbx_test",
      state: "SANDBOX_STATE_RUNNING",
      policy: { resources: { memMib: 3072, maxMemMib: 16384, bootMemMib: 1024 } },
    },
    memMib: {
      change: "RESOURCE_CHANGE_PARTIAL",
      previous: 8192,
      value: 3072,
      reason: "pages it could not move",
    },
  });
  const updated = await sandbox.updateResources({ memoryMib: 1024 });
  assert.deepEqual(updated.memoryMib, {
    change: "partial",
    previous: 8192,
    value: 3072,
    reason: "pages it could not move",
  });
  assert.equal(sandbox.memoryMib, 3072);
  assert.equal(sandbox.maxMemoryMib, 16384);
  assert.equal(sandbox.policy.resources.bootMemoryMib, 1024);
});

test("a growth limit goes out with a create policy", async () => {
  const { toResourcePolicy } = await import("../dist/policy.js");
  assert.deepEqual(toResourcePolicy({ memoryMib: 1024, maxMemoryMib: 16384 }), {
    vcpus: 0,
    memMib: 1024,
    diskMib: 0,
    cpus: 0,
    reservedCpus: 0,
    cpuShares: 0,
    cpusetCpus: "",
    blkioWeight: 0,
    maxMemMib: 16384,
  });
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

test("a lifetime update can turn checkpoints on, and a record says how old the latest is", async () => {
  const at = Date.UTC(2026, 10, 12, 9, 30);
  const { sandbox, calls } = sandboxAnswering({
    id: "sbx_test",
    state: "SANDBOX_STATE_RUNNING",
    policy: { lifetime: { checkpointSecs: "300", isMemoryCheckpointed: true } },
    checkpointAtUnixMs: String(at),
    checkpointKind: "CHECKPOINT_KIND_MEMORY",
  });
  const info = await sandbox.updateLifetime({ checkpointSecs: 300, checkpointMemory: true });
  assert.equal(calls[0].method, "UpdateLifetime");
  assert.equal(calls[0].request.checkpointSecs, 300);
  assert.equal(calls[0].request.isMemoryCheckpointed, true);
  assert.equal(info.policy.lifetime.checkpointSecs, 300);
  assert.equal(info.policy.lifetime.checkpointMemory, true);
  assert.equal(info.checkpointAt.getTime(), at);
  assert.equal(info.checkpointKind, "memory");

  const none = fakeSandbox({}, {});
  assert.equal(none.info.checkpointAt, null);
  assert.equal(none.info.checkpointKind, null);
});
