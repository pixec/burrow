// `sandbox.fs` is `fs/promises`: the same calls produce the same shapes, and
// a kernel error is indistinguishable from one Node's own `fs` raised.

import assert from "node:assert/strict";
import { open as hostOpen } from "node:fs/promises";
import { test } from "node:test";

import { BurrowError, Sandbox } from "../dist/index.js";

/**
 * A sandbox whose node answers every `Fs` call with `answer(op, body)`, and
 * records what was asked. `answer` returns the response's oneof as
 * `{ [tag]: value }`, the way proto-loader decodes it.
 */
function fsSandbox(answer, { download } = {}) {
  const calls = [];
  const node = {
    async unary(method, request) {
      assert.equal(method, "Fs");
      const op = Object.keys(request).find((key) => key !== "sandboxId" && key !== "user");
      calls.push({ op, body: request[op], user: request.user });
      const [result, value] = Object.entries(await answer(op, request[op]))[0];
      return { result, [result]: value };
    },
    async *serverStream(method, request) {
      assert.equal(method, "DownloadFile");
      calls.push({ op: "download", body: request });
      yield* download(request.path);
    },
  };
  const sandbox = Sandbox.adopt(
    { route: () => node },
    { id: "sbx_test", state: "SANDBOX_STATE_RUNNING" },
  );
  return { sandbox, calls };
}

const ENOENT = { code: "ENOENT", errno: 2, syscall: "open", path: "/x", dest: "" };

test("a kernel error is shaped as Node's own", async () => {
  const { sandbox } = fsSandbox(() => ({ error: ENOENT }));
  const theirs = await hostOpen("/burrow-sdk-test-does-not-exist").catch((err) => err);
  const ours = await sandbox.fs.open("/x").catch((err) => err);

  assert.ok(ours instanceof Error);
  assert.equal(ours.message, "ENOENT: no such file or directory, open '/x'");
  assert.equal(ours.code, "ENOENT");
  assert.equal(ours.errno, -2);
  assert.equal(ours.syscall, "open");
  assert.equal(ours.path, "/x");
  assert.equal("dest" in ours, false);
  // The same own properties, and the same message, but for the path.
  assert.deepEqual(Object.keys(ours).sort(), Object.keys(theirs).sort());
  assert.equal(
    ours.message.replace("/x", "P"),
    theirs.message.replace("/burrow-sdk-test-does-not-exist", "P"),
  );
});

test("a two-path error names both, as rename's does", async () => {
  const { sandbox } = fsSandbox(() => ({
    error: { code: "EXDEV", errno: 18, syscall: "rename", path: "/a", dest: "/b" },
  }));
  await assert.rejects(sandbox.fs.rename("/a", "/b"), {
    message: "EXDEV: cross-device link not permitted, rename '/a' -> '/b'",
    code: "EXDEV",
    errno: -18,
    path: "/a",
    dest: "/b",
  });
});

test("a policy refusal stays a BurrowError", async () => {
  const { sandbox } = fsSandbox(() => {
    throw new BurrowError("path is outside the sandbox's file scope", "permission_denied");
  });
  await assert.rejects(sandbox.fs.stat("/etc/shadow"), (err) => {
    assert.ok(err instanceof BurrowError);
    assert.equal(err.code, "permission_denied");
    return true;
  });
});

test("string flags map to Linux's open(2) values", async () => {
  const { sandbox, calls } = fsSandbox(() => ({ handle: 3 }));
  const expected = {
    r: 0,
    "r+": 0o2,
    w: 0o1101,
    "w+": 0o1102,
    a: 0o2101,
    "a+": 0o2102,
    wx: 0o1301,
    "wx+": 0o1302,
    ax: 0o2301,
    "ax+": 0o2302,
  };
  for (const [flag, value] of Object.entries(expected)) {
    await sandbox.fs.open("/f", flag);
    assert.equal(calls.at(-1).body.flags, value, flag);
  }
  await sandbox.fs.open("/f");
  assert.equal(calls.at(-1).body.flags, 0, "defaults to r");
  assert.equal(calls.at(-1).body.mode, 0o666);
  await sandbox.fs.open("/f", 0o102, "644");
  assert.deepEqual(calls.at(-1).body, { path: "/f", flags: 0o102, mode: 0o644 });

  await assert.rejects(sandbox.fs.open("/f", "rw"), {
    name: "TypeError",
    code: "ERR_INVALID_ARG_VALUE",
  });
});

/** An in-memory file behind one handle, read and written by position. */
function fileSandbox(initial = "") {
  let content = Buffer.from(initial);
  let cursor = 0;
  return fsSandbox((op, body) => {
    switch (op) {
      case "open":
        return { handle: 7 };
      case "read": {
        const from = body.position < 0 ? cursor : body.position;
        const data = content.subarray(from, from + body.length);
        if (body.position < 0) cursor += data.length;
        return { data };
      }
      case "write": {
        const at = body.position < 0 ? cursor : body.position;
        const next = Buffer.alloc(Math.max(content.length, at + body.data.length));
        content.copy(next);
        Buffer.from(body.data).copy(next, at);
        content = next;
        if (body.position < 0) cursor += body.data.length;
        return { written: body.data.length };
      }
      case "close":
        return { isDone: true };
    }
    throw new Error(`unexpected ${op}`);
  });
}

test("a handle reads and writes by position", async () => {
  const { sandbox, calls } = fileSandbox("0123456789");
  const handle = await sandbox.fs.open("/f", "r+");
  assert.equal(handle.fd, 7);

  const buffer = Buffer.alloc(8, ".");
  const read = await handle.read(buffer, 2, 3, 4);
  assert.equal(read.bytesRead, 3);
  assert.equal(read.buffer, buffer);
  assert.equal(buffer.toString(), "..456...");
  assert.deepEqual(calls.at(-1).body, { handle: 7, position: 4, length: 3 });

  // No position reads from the handle's own, which advances.
  await handle.read({ buffer: Buffer.alloc(2) });
  assert.equal(calls.at(-1).body.position, -1);

  const written = await handle.write(Buffer.from("ab"), 0, 2, 8);
  assert.deepEqual(written, { bytesWritten: 2, buffer: Buffer.from("ab") });
  assert.equal(calls.at(-1).body.position, 8);

  const text = await handle.write("€", 0, "utf8");
  assert.deepEqual(text, { bytesWritten: 3, buffer: "€" });

  assert.equal(
    (await handle.read({ buffer: Buffer.alloc(16), position: 0 })).buffer.toString("utf8", 0, 10),
    "€34567ab",
  );
});

test("a closed handle rejects with EBADF, as Node's does", async () => {
  const { sandbox, calls } = fileSandbox("x");
  const handle = await sandbox.fs.open("/f");
  await handle.close();
  assert.equal(handle.fd, -1);

  await assert.rejects(handle.read(Buffer.alloc(1), 0, 1, 0), {
    message: "file closed",
    code: "EBADF",
    syscall: "read",
  });
  await assert.rejects(handle.stat(), { code: "EBADF", syscall: "fstat" });
  // A second close is a no-op, not a second call.
  await handle.close();
  assert.equal(calls.filter((call) => call.op === "close").length, 1);
});

test("writeFile opens, writes and closes, as the handle's user", async () => {
  const { sandbox, calls } = fileSandbox();
  await sandbox.asUser("alice").fs.writeFile("/home/alice/a.txt", "hi", { mode: 0o600 });
  assert.deepEqual(
    calls.map((call) => call.op),
    ["open", "write", "close"],
  );
  assert.deepEqual(calls[0].body, { path: "/home/alice/a.txt", flags: 0o1101, mode: 0o600 });
  assert.ok(calls.every((call) => call.user === "alice"));
});

test("readdir with file types returns Dirents, and stats what d_type left unknown", async () => {
  const { sandbox, calls } = fsSandbox((op, body) => {
    if (op === "readDir") {
      return {
        entries: {
          entries: [
            { name: "a.txt", type: "file" },
            { name: "src", type: "dir" },
            { name: "link", type: "symlink" },
            { name: "pipe", type: "unknown" },
          ],
        },
      };
    }
    assert.equal(op, "stat");
    assert.deepEqual(body, { path: "/work/pipe", isNofollow: true });
    return { stat: { mode: 0o10644 } };
  });

  const entries = await sandbox.fs.readdir("/work", { withFileTypes: true });
  assert.deepEqual(
    entries.map((e) => [e.name, e.isFile(), e.isDirectory(), e.isSymbolicLink(), e.isFIFO()]),
    [
      ["a.txt", true, false, false, false],
      ["src", false, true, false, false],
      ["link", false, false, true, false],
      ["pipe", false, false, false, true],
    ],
  );
  assert.equal(entries[0].parentPath, "/work");
  assert.equal(calls[0].op, "readDir");

  assert.deepEqual(await sandbox.fs.readdir("/work"), ["a.txt", "src", "link", "pipe"]);
});

test("a recursive readdir names entries by their path below the root", async () => {
  const tree = {
    "/w": [{ name: "a", type: "dir" }, { name: "f", type: "file" }],
    "/w/a": [{ name: "g", type: "file" }],
  };
  const { sandbox } = fsSandbox((_op, body) => ({ entries: { entries: tree[body.path] } }));
  assert.deepEqual(await sandbox.fs.readdir("/w", { recursive: true }), ["a", "f", "a/g"]);
});

test("mkdir resolves the first directory a recursive call created", async () => {
  let created = "/a/b";
  const { sandbox, calls } = fsSandbox(() => (created === null ? { isDone: true } : { path: created }));

  assert.equal(await sandbox.fs.mkdir("/a/b/c", { recursive: true }), "/a/b");
  assert.deepEqual(calls.at(-1).body, { path: "/a/b/c", mode: 0o777, isRecursive: true });

  created = "";
  assert.equal(await sandbox.fs.mkdir("/a/b/c", { recursive: true }), undefined);

  created = null;
  assert.equal(await sandbox.fs.mkdir("/d", 0o750), undefined);
  assert.deepEqual(calls.at(-1).body, { path: "/d", mode: 0o750, isRecursive: false });
});

test("stat converts times and types as Node's Stats does", async () => {
  const { sandbox } = fsSandbox(() => ({
    stat: {
      dev: 1,
      ino: 2,
      mode: 0o100644,
      nlink: 1,
      uid: 1000,
      gid: 1000,
      rdev: 0,
      size: 12,
      blksize: 4096,
      blocks: 8,
      atimeNs: 1_700_000_000_250_000_000,
      mtimeNs: 1_700_000_000_000_000_000,
      ctimeNs: 1_700_000_000_000_000_000,
      birthtimeNs: 0,
    },
  }));
  const stats = await sandbox.fs.stat("/f");
  assert.equal(stats.isFile(), true);
  assert.equal(stats.isDirectory(), false);
  assert.equal(stats.size, 12);
  assert.equal(stats.atimeMs, 1_700_000_000_250);
  assert.deepEqual(stats.mtime, new Date(1_700_000_000_000));
});

test("utimes takes Dates, seconds and numeric strings", async () => {
  const { sandbox, calls } = fsSandbox(() => ({ isDone: true }));
  await sandbox.fs.utimes("/f", new Date(1_500), "2.25");
  assert.deepEqual(calls.at(-1).body, {
    path: "/f",
    atimeNs: "1500000000",
    mtimeNs: "2250000000",
    isNofollow: false,
  });
});

test("readFile streams the whole file in one call", async () => {
  const { sandbox, calls } = fsSandbox(() => assert.fail("no Fs call expected"), {
    async *download() {
      yield { data: Buffer.from("hello ") };
      yield { data: Buffer.from("world") };
    },
  });
  assert.equal(await sandbox.fs.readFile("/f", "utf8"), "hello world");
  assert.deepEqual(await sandbox.fs.readFile("/f"), Buffer.from("hello world"));
  assert.deepEqual(calls.map((call) => call.op), ["download", "download"]);
});

// The download stream has no errno to give, so a failure is asked again the
// long way, which comes back as the kernel's error.
test("a download that fails is read the long way, for the kernel's error", async () => {
  const { sandbox } = fsSandbox(() => ({ error: ENOENT }), {
    // A generator that fails on its first pull, as a stream refused up front does.
    async *download() {
      yield* [];
      throw new BurrowError("no such file", "not_found");
    },
  });
  await assert.rejects(sandbox.fs.readFile("/x"), { code: "ENOENT", syscall: "open" });
});
