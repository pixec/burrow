// Present replaces, absent leaves.
//
// The section that is *not* sent is the interesting one: the node reads an
// absent section as "leave this policy alone", so the SDK must not fill one in.

import assert from "node:assert/strict";
import { test } from "node:test";

import { Sandbox } from "../dist/index.js";

function recordingSandbox() {
  const sent = [];
  const transport = {
    async unary(method, request) {
      sent.push({ method, request });
      return { id: "sbx_test", state: "SANDBOX_STATE_RUNNING" };
    },
  };
  const sandbox = Sandbox.adopt(transport, {
    id: "sbx_test",
    state: "SANDBOX_STATE_RUNNING",
  });
  return { sandbox, sent };
}

test("tightening files says nothing about exec", async () => {
  const { sandbox, sent } = recordingSandbox();
  await sandbox.updateAccessPolicy({
    fs: { allowUpload: false, pathScopes: ["/work"] },
  });

  assert.equal(sent.length, 1);
  const { method, request } = sent[0];
  assert.equal(method, "UpdateAccessPolicy");
  assert.equal(
    request.exec,
    undefined,
    "an exec section was invented, which would re-open exec",
  );
  assert.deepEqual(request.fs, {
    isUploadAllowed: false,
    isDownloadAllowed: true,
    pathScopes: ["/work"],
    maxUploadBytes: 0,
  });
});

test("denying exec says nothing about files", async () => {
  const { sandbox, sent } = recordingSandbox();
  await sandbox.updateAccessPolicy({ exec: { allowExec: false } });

  assert.deepEqual(sent[0].request.exec, { isExecAllowed: false });
  assert.equal(sent[0].request.fs, undefined);
});

test("both sections travel together when both are named", async () => {
  const { sandbox, sent } = recordingSandbox();
  await sandbox.updateAccessPolicy({
    exec: { allowExec: true },
    fs: { allowDownload: false },
  });

  const call = sent.find((c) => c.method === "UpdateAccessPolicy");
  assert.deepEqual(call.request.exec, { isExecAllowed: true });
  assert.equal(call.request.fs.isDownloadAllowed, false);
  // A present section is replaced whole, so the fields not restated take
  // their permissive defaults rather than being carried over.
  assert.equal(call.request.fs.isUploadAllowed, true);
});

test("naming neither section is refused rather than sent", async () => {
  const { sandbox, sent } = recordingSandbox();
  await assert.rejects(() => sandbox.updateAccessPolicy({}), {
    code: "invalid_argument",
  });
  assert.deepEqual(sent, []);
});
