// Ingress rules and public IPs, as they reach and come back from the wire.

import assert from "node:assert/strict";
import { test } from "node:test";

import { Ips, toPublicIp } from "../dist/ip.js";
import { fromNetworkPolicy, toNetworkPolicy } from "../dist/policy.js";

test("ingress rules go out as the proto spells them and read back the same", () => {
  const ingress = [
    { protocol: "tcp", ports: [25, 587] },
    { protocol: "tcp", ports: [22], sources: ["203.0.113.0/24"] },
    { protocol: "udp", ports: ["27000-27015"] },
    { protocol: "icmp" },
    {},
  ];
  const wire = toNetworkPolicy({ mode: "open", ingress });
  assert.deepEqual(wire.ingress[0], {
    protocol: "INGRESS_PROTOCOL_TCP",
    ports: [
      { port: 25, portEnd: 0 },
      { port: 587, portEnd: 0 },
    ],
    sources: [],
  });
  assert.deepEqual(wire.ingress[2].ports, [{ port: 27000, portEnd: 27015 }]);
  assert.equal(wire.ingress[4].protocol, "INGRESS_PROTOCOL_UNSPECIFIED");
  assert.deepEqual(fromNetworkPolicy(wire).ingress, ingress);
});

test("a misspelt ingress rule is refused rather than widened", () => {
  assert.throws(() => toNetworkPolicy({ ingress: [{ protocol: "sctp" }] }), /unknown protocol/);
  assert.throws(() => toNetworkPolicy({ ingress: [{ port: 22 }] }), /unknown key "port"/);
  assert.throws(() => toNetworkPolicy({ ingress: [{ ports: ["22-"] }] }), /not N or N-M/);
});

test("a public ip reads back with its enums named and its stamps as dates", () => {
  const ip = toPublicIp({
    address: "203.0.113.17",
    family: 4,
    prefixLen: 32,
    pool: "rack-a",
    nodeId: "node-a",
    state: "PUBLIC_IP_STATE_ALLOCATED",
    sandboxId: "sbx_a",
    allocatedAtUnixMs: "1700000000000",
  });
  assert.equal(ip.nodeId, "node-a");
  assert.equal(ip.state, "allocated");
  assert.equal(ip.allocatedAt.getTime(), 1700000000000);
  assert.equal(ip.attachedAt, null);
  assert.equal(ip.sandboxId, "sbx_a");
  assert.equal(ip.nodePrefix, false);
  assert.equal(toPublicIp({ pool: "node:node-a", isNodePrefix: true }).nodePrefix, true);
});

test("allocating for a sandbox and creating a pool send the wire's names", async () => {
  const calls = [];
  const transport = {
    async unary(method, request) {
      calls.push({ method, request });
      return method === "CreateIpPool" ? { ...request, total: 15 } : { address: "203.0.113.17" };
    },
  };
  const ips = new Ips(transport);
  await ips.allocate({ sandboxId: "api" });
  assert.deepEqual(calls[0], {
    method: "AllocateIp",
    request: { pool: "", family: 4, sandboxId: "api" },
  });
  const pool = await ips.createPool({ name: "rack-a", nodeId: "node-a", onLink: true });
  assert.equal(calls[1].request.isOnLink, true);
  assert.equal("provider" in calls[1].request, false);
  assert.equal(pool.total, 15);
});

test("a drain can keep sandboxes pinned by their public ips", async () => {
  const { fakeBurrow } = await import("./helpers.mjs");
  const calls = [];
  const burrow = fakeBurrow({
    async unary(method, request) {
      calls.push({ method, request });
      return { suspended: 2, pinnedSandboxIds: ["sbx_a"] };
    },
  });
  const res = await burrow.drainNode("node-a", { suspend: true, keepPinned: true });
  assert.deepEqual(calls[0].request, {
    nodeId: "node-a",
    isDraining: true,
    isSuspending: true,
    isPinnedKept: true,
  });
  assert.deepEqual(res, { suspended: 2, pinnedSandboxIds: ["sbx_a"] });
});
