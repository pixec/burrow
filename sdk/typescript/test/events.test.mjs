// `events()` maps the lifecycle log and only drops the deadline when following,
// since a follow is meant to stay open.

import assert from "node:assert/strict";
import { test } from "node:test";

import { Snapshot } from "../dist/index.js";
import { fakeBurrow } from "./helpers.mjs";

function burrowStreaming(rows, calls) {
  return fakeBurrow({
    async *serverStream(method, request, timeoutMs) {
      calls.push({ method, request, timeoutMs });
      yield* rows;
    },
  });
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
        kind: "EVENT_KIND_STARTED",
        state: "SANDBOX_STATE_RUNNING",
        detail: "boot",
        template: "python",
        tags: { team: "ml" },
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
  for await (const event of burrow.events({ after: 47, sandboxId: "build-482", limit: 5 })) {
    events.push(event);
  }
  assert.deepEqual(calls, [
    {
      method: "TailEvents",
      request: { afterSeq: 47, sandboxId: "build-482", isFollow: false, limit: 5 },
      timeoutMs: undefined,
    },
  ]);
  assert.deepEqual(events, [
    {
      seq: 48,
      nodeId: "node-1",
      nodeSeq: 7,
      at: new Date(1_790_000_000_000),
      sandboxId: "sbx_a",
      kind: "started",
      state: "running",
      detail: "boot",
      template: "python",
      tags: { team: "ml" },
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
  const snapshot = new Snapshot(
    { close() {} },
    {
      id: "snap_a",
      isDurable: true,
      arch: "aarch64",
      hypervisor: "firecracker",
      hypervisorVersion: "1.13.1",
      resources: { vcpus: 2, memMib: 1024, diskMib: 2048 },
      createdAtUnixMs: 1_790_000_000_000,
    },
  );
  assert.equal(snapshot.durable, true);
  assert.equal(snapshot.arch, "aarch64");
  assert.equal(snapshot.hypervisorVersion, "1.13.1");
  assert.deepEqual(snapshot.resources, { vcpus: 2, memoryMib: 1024, diskMib: 2048 });
  assert.equal(snapshot.createdAt.getTime(), 1_790_000_000_000);
  assert.equal(snapshot.expiresAt, null);
  assert.equal(snapshot.nodeId, "");
});

test("usage maps the query and the report", async () => {
  const calls = [];
  const burrow = fakeBurrow({
    async unary(method, request) {
      calls.push({ method, request });
      return {
        intervals: [
          {
            id: 9,
            sandboxId: "sbx_a",
            nodeId: "node-1",
            template: "python",
            tags: { customer: "acme" },
            state: "USAGE_STATE_RUNNING",
            vcpus: 2,
            memMib: 2048,
            startedAtUnixMs: 1_000,
            endedAtUnixMs: 61_000,
            cpuUsageUsec: 5_000_000,
            rxBytes: 10,
            txBytes: 20,
            closedBy: "stopped",
          },
        ],
        nextAfterId: 9,
      };
    },
  });
  const report = await burrow.usage({
    from: new Date(Date.UTC(2026, 9, 1)),
    to: 1_793_491_200_000,
    tags: { customer: "acme" },
    groupBy: "tag:customer",
    limit: 1,
  });
  assert.deepEqual(calls, [
    {
      method: "QueryUsage",
      request: {
        fromUnixMs: 1_790_812_800_000,
        toUnixMs: 1_793_491_200_000,
        sandboxId: "",
        tags: { customer: "acme" },
        groupBy: "USAGE_GROUP_TAG",
        groupByTag: "customer",
        afterId: 0,
        limit: 1,
        isOpenIncluded: true,
      },
    },
  ]);
  assert.equal(report.nextAfterId, 9);
  assert.deepEqual(report.sums, []);
  assert.deepEqual(report.intervals[0], {
    id: 9,
    sandboxId: "sbx_a",
    nodeId: "node-1",
    template: "python",
    tags: { customer: "acme" },
    state: "running",
    vcpus: 2,
    memoryMib: 2048,
    startedAt: new Date(1_000),
    endedAt: new Date(61_000),
    cpuUsageUsec: 5_000_000,
    rxBytes: 10,
    txBytes: 20,
    closedBy: "stopped",
    open: false,
  });
});
