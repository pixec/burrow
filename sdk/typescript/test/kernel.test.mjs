// A template's kernel, as a build names it and as records report it.

import assert from "node:assert/strict";
import { test } from "node:test";

import { Template } from "../dist/index.js";
import { toSandboxInfo } from "../dist/sandbox.js";
import { toTemplateInfo } from "../dist/template.js";
import { fakeBurrow, fakeSandbox } from "./helpers.mjs";

const kernel = {
  name: "ch-linux",
  digest: "ab".repeat(32),
  version: "7.2.8+",
  arch: "x86_64",
  capabilities: { isKvmBuiltIn: true, isVirtioMemBuiltIn: true, isVsockBuiltIn: true, isVirtioBlkBuiltIn: true, isExt4BuiltIn: true },
  detectedFrom: "strings",
};

const parsed = {
  name: "ch-linux",
  digest: "ab".repeat(32),
  version: "7.2.8+",
  arch: "x86_64",
  capabilities: { kvm: true, virtioMem: true, vsock: true, virtioBlk: true, ext4: true },
  detectedFrom: "strings",
};

test("a build names its kernel, and leaves it to the node when it does not", () => {
  const template = Template().fromImage("alpine:3.20");
  assert.equal(template.toRequest("t", { kernel: "ch-linux" }).kernel, "ch-linux");
  assert.equal(template.toRequest("t", {}).kernel, "");
});

test("a template and a sandbox report the kernel they boot", () => {
  assert.deepEqual(toTemplateInfo({ name: "t", kernel }).kernel, parsed);
  assert.equal(toTemplateInfo({ name: "t" }).kernel, null);
  assert.deepEqual(toSandboxInfo({ id: "s", kernel }).kernel, parsed);
});

test("a boot takes the template's current kernel unless told to keep its own", async () => {
  const calls = [];
  const transport = {
    async unary(method, request) {
      calls.push({ method, request });
      return { id: "sbx_test", state: "SANDBOX_STATE_RUNNING" };
    },
  };
  const sandbox = fakeSandbox(transport, { state: "SANDBOX_STATE_STOPPED" });
  await sandbox.start();
  await sandbox.start({ keepKernel: true });
  assert.deepEqual(
    calls.map((c) => c.request),
    [
      { sandboxId: "sbx_test", isKernelKept: false },
      { sandboxId: "sbx_test", isKernelKept: true },
    ],
  );
});

test("a node lists its kernels and which hypervisors each is the default for", async () => {
  const burrow = fakeBurrow({
    async unary() {
      return {
        nodes: [{ info: { id: "n", kernels: [{ ...kernel, hypervisors: ["cloud-hypervisor"], defaultFor: ["cloud-hypervisor"] }] } }],
      };
    },
  });
  const [node] = await burrow.nodes();
  assert.deepEqual(node.kernels, [
    { ...parsed, hypervisors: ["cloud-hypervisor"], defaultFor: ["cloud-hypervisor"] },
  ]);
});
