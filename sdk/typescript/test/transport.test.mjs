// Constructing a `Transport` never blocks on the network (grpc-js dials
// lazily), so these check the "should this even try to connect" decision
// on its own, without a server behind it.

import assert from "node:assert/strict";
import { test } from "node:test";

import { Transport } from "../dist/transport.js";

/** Constructs a transport and closes the channel it opened. */
function transport(options) {
  const t = new Transport(options);
  t.close();
  return t;
}

test("an api key over a bare endpoint with no scheme is refused", () => {
  assert.throws(
    () => transport({ endpoint: "orchestrator.example.com:7070", apiKey: "secret" }),
    /plaintext/,
  );
});

test("an api key to localhost is fine with no tls option", () => {
  assert.doesNotThrow(() =>
    transport({ endpoint: "localhost:7070", apiKey: "secret" }),
  );
  assert.doesNotThrow(() =>
    transport({ endpoint: "127.0.0.1:7070", apiKey: "secret" }),
  );
});

test("an explicit tls choice is always honoured, api key or not", () => {
  assert.doesNotThrow(() =>
    transport({
      endpoint: "orchestrator.example.com:7070",
      apiKey: "secret",
      tls: false,
    }),
  );
  assert.doesNotThrow(() =>
    transport({
      endpoint: "orchestrator.example.com:7070",
      apiKey: "secret",
      tls: true,
    }),
  );
});

test("an explicit http scheme is treated as the caller's own choice", () => {
  assert.doesNotThrow(() =>
    transport({ endpoint: "http://orchestrator.example.com:7070", apiKey: "secret" }),
  );
});

test("an https endpoint needs no api-key opt-in", () => {
  assert.doesNotThrow(() =>
    transport({ endpoint: "https://orchestrator.example.com", apiKey: "secret" }),
  );
});

test("no api key at all is never refused, plaintext or not", () => {
  assert.doesNotThrow(() =>
    transport({ endpoint: "orchestrator.example.com:7070" }),
  );
});
