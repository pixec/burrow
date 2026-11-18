// Builds: the tag and build a listing names, and the build a sandbox records.

import assert from "node:assert/strict";
import { test } from "node:test";

import { toSandboxInfo } from "../dist/sandbox.js";
import { TemplateBuilder, toTemplateInfo } from "../dist/template.js";

const digest = `sha256:${"ab".repeat(32)}`;

test("a listing names the tag and the build it resolves to", () => {
  const info = toTemplateInfo({ name: "t", tag: "v1", digest, status: "ready" });
  assert.deepEqual([info.tag, info.digest, info.status], ["v1", digest, "ready"]);
  assert.equal(toSandboxInfo({ id: "s", buildDigest: digest }).buildDigest, digest);
});

test("a disk import names the disk, its node and the TPM", () => {
  const request = new TemplateBuilder().fromDisk("win.raw", "node_a", { tpm: true }).toRequest("win11", {});
  assert.deepEqual(
    [request.from, request.fromDisk, request.nodeId, request.isTpm],
    ["", "win.raw", "node_a", true],
  );
});
