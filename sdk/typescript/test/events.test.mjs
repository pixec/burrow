// `events()` maps the lifecycle log and only drops the deadline when following,
// since a follow is meant to stay open.

import assert from "node:assert/strict";
import { test } from "node:test";

import { Burrow, Snapshot } from "../dist/index.js";

function burrowStreaming(rows, calls) {
  const burrow = new Burrow({ endpoint: "localhost:1" });
  burrow.close();
  burrow.transport = {
    async *serverStream(method, request, timeoutMs) {
      calls.push({ method, request, timeoutMs });
      yield* rows;
    },
  };
  return burrow;
}

test("events maps the request and each row", async () => {
  const calls = [];
  const burrow = burrowStreaming(
    [
      {
        seq: 48,
        nodeId: "node-1",
        nodeSeq: 7,
        atUnixMs: 1_790_000_000_000,
        sandboxId: "sbx_a",
        type: "started",
        state: "SANDBOX_STATE_RUNNING",
        detail: "boot",
        template: "python",
        metadata: { team: "ml" },
        cpuUsageUsec: 1200,
        rxBytes: 10,
        txBytes: 20,
        vcpus: 2,
        memMib: 1024,
      },
    ],
    calls,
  );
  const events = [];
  for await (const event of burrow.events({ after: 47, sandbox: "build-482", limit: 5 })) {
    events.push(event);
  }
  assert.deepEqual(calls, [
    {
      method: "TailEvents",
      request: { afterSeq: 47, sandbox: "build-482", isFollow: false, limit: 5 },
      timeoutMs: undefined,
    },
  ]);
  assert.deepEqual(events, [
    {
      seq: 48,
      nodeId: "node-1",
      nodeSeq: 7,
      atUnixMs: 1_790_000_000_000,
      sandboxId: "sbx_a",
      type: "started",
      state: "running",
      detail: "boot",
      template: "python",
      metadata: { team: "ml" },
      cpuUsageUsec: 1200,
      rxBytes: 10,
      txBytes: 20,
      vcpus: 2,
      memoryMib: 1024,
    },
  ]);
});

test("a follow has no deadline", async () => {
  const calls = [];
  const burrow = burrowStreaming([], calls);
  for await (const _ of burrow.events({ follow: true })) {
    // empty
  }
  assert.equal(calls[0].request.isFollow, true);
  assert.equal(calls[0].timeoutMs, Infinity);
});

test("a snapshot surfaces where it can be restored", () => {
  const snapshot = Snapshot.adopt(
    { close() {} },
    { id: "snap_a", isDurable: true, arch: "aarch64", firecrackerVersion: "1.13.1" },
  );
  assert.equal(snapshot.isDurable, true);
  assert.equal(snapshot.arch, "aarch64");
  assert.equal(snapshot.firecrackerVersion, "1.13.1");
  assert.equal(snapshot.nodeId, "");
});
