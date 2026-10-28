// `stat` and `exists` answer from the parent listing, so a missing name and a
// missing parent both read as "not there" rather than as an error.

import assert from "node:assert/strict";
import { test } from "node:test";

import { BurrowError, Sandbox } from "../dist/index.js";

function sandboxListing(entries) {
  return Sandbox.adopt(
    {
      // List calls go wherever the route sends them; this stub is both.
      route() {
        return this;
      },
      async unary(method, request) {
        assert.equal(method, "ListDir");
        if (request.path === "/gone") throw new BurrowError("no such directory", "not_found");
        return { entries };
      },
    },
    { id: "sbx_test", state: "SANDBOX_STATE_RUNNING" },
  );
}

test("stat describes a listed entry and names its path", async () => {
  const sandbox = sandboxListing([{ name: "app.py", isDir: false, size: 3, mode: 0o644 }]);
  assert.deepEqual(await sandbox.stat("/work/app.py"), {
    path: "/work/app.py",
    name: "app.py",
    isDir: false,
    size: 3,
    mode: 0o644,
    type: "file",
  });
  assert.equal(await sandbox.exists("/work/app.py"), true);
  assert.equal(await sandbox.exists("/work/nope"), false);
});

test("a missing parent is null, not an error", async () => {
  const sandbox = sandboxListing([]);
  assert.equal(await sandbox.stat("/gone/x"), null);
  assert.equal((await sandbox.stat("/")).type, "dir");
});

test("the namespaces point at the same methods", () => {
  const sandbox = sandboxListing([]);
  assert.equal(sandbox.files, undefined);
  assert.equal(typeof sandbox.fs.rm, "function");
  assert.rejects(sandbox.fs.stat("/work/nope"), (err) => err.code === "not_found");
  assert.equal(typeof sandbox.commands.kill, "function");
  assert.equal(typeof sandbox.pty.create, "function");
});
