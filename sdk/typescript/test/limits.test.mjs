// A full file chunk over a real connection, on both routes: relayed through
// a stand-in orchestrator, and direct to a stand-in node it grants.

import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";

import { MAX_FILE_CHUNK, MAX_MESSAGE_BYTES, Transport } from "../dist/transport.js";

const proto = resolve(dirname(fileURLToPath(import.meta.url)), "../proto");
const pkg = grpc.loadPackageDefinition(
  protoLoader.loadSync("api.proto", { includeDirs: [proto], longs: Number, defaults: true, oneofs: true }),
).burrow.api.v1;

/** Answers Fs as a guest would: writes report their length, reads fill it. */
function fs(call, callback) {
  const { write, read } = call.request;
  if (write) callback(null, { written: write.data.length });
  else callback(null, { data: Buffer.alloc(read.length, 1) });
}

async function serve() {
  const server = new grpc.Server({
    "grpc.max_receive_message_length": MAX_MESSAGE_BYTES,
    "grpc.max_send_message_length": MAX_MESSAGE_BYTES,
  });
  let endpoint;
  server.addService(pkg.Burrow.service, {
    Fs: fs,
    IssueAccess: (call, callback) =>
      callback(null, {
        endpoint,
        token: "t",
        sandboxId: call.request.sandboxId,
        expiresAtUnixMs: Date.now() + 600_000,
      }),
  });
  server.addService(pkg.Access.service, { Fs: fs });
  const port = await new Promise((ok, fail) =>
    server.bindAsync("127.0.0.1:0", grpc.ServerCredentials.createInsecure(), (err, port) =>
      err ? fail(err) : ok(port),
    ),
  );
  endpoint = `http://127.0.0.1:${port}`;
  return { server, endpoint };
}

for (const route of ["orchestrator", "direct"]) {
  test(`a full chunk is written and read in one call, ${route}`, async () => {
    const { server, endpoint } = await serve();
    const transport = new Transport({ endpoint, route });
    try {
      const target = transport.route("sbx_a");
      const written = await target.unary("Fs", {
        sandboxId: "sbx_a",
        write: { handle: 1, position: 0, data: Buffer.alloc(MAX_FILE_CHUNK) },
      });
      assert.equal(Number(written.written), MAX_FILE_CHUNK);
      const read = await target.unary("Fs", {
        sandboxId: "sbx_a",
        read: { handle: 1, position: 0, length: MAX_FILE_CHUNK },
      });
      assert.equal(read.data.length, MAX_FILE_CHUNK);
    } finally {
      transport.close();
      server.forceShutdown();
    }
  });
}

test("a message past the limit is refused before it is sent", async () => {
  const { server, endpoint } = await serve();
  const transport = new Transport({ endpoint, route: "orchestrator" });
  try {
    await assert.rejects(
      transport.unary("Fs", {
        sandboxId: "sbx_a",
        write: { handle: 1, position: 0, data: Buffer.alloc(MAX_MESSAGE_BYTES) },
      }),
      (err) => err.code === "resource_exhausted",
    );
  } finally {
    transport.close();
    server.forceShutdown();
  }
});
