// Rules a JavaScript caller can write that TypeScript would have refused, and
// what reaches the wire from the ones it would not.
//
// The SDK's own examples are .mjs, so excess-property checking is not the last
// line of defence here: these keys have to be handled at runtime too.

import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import protoLoader from "@grpc/proto-loader";

import {
  fromNetworkPolicy,
  resolveNetwork,
  toNetworkPolicy,
} from "../dist/policy.js";

/** The narrowest policy that carries one rule, on the wire. */
function withRule(rule) {
  return toNetworkPolicy({
    mode: "allowlist",
    allowDomains: ["api.github.com"],
    inspectTls: true,
    rules: [{ domain: "api.github.com", ...rule }],
  });
}

test("a bare mode is a policy with only that mode", () => {
  assert.deepEqual(resolveNetwork("open"), { mode: "open" });
  assert.deepEqual(resolveNetwork(undefined), {});
});

test("a rule that sets headers is carried onto the wire", () => {
  const wire = withRule({ setHeaders: { Authorization: "Bearer t" } });
  assert.deepEqual(wire.rules, [
    {
      domain: "api.github.com",
      match: undefined,
      setHeaders: { headers: [{ name: "Authorization", value: "Bearer t" }] },
    },
  ]);
  assert.equal(wire.isTlsInspected, true);
});

// A matcher selects which requests the rule acts on. It never blocks: a
// request matching nothing is still allowed, it just goes unmodified.
test("a request matcher is carried onto the wire", () => {
  const wire = withRule({
    match: {
      path: { startsWith: "/repos/" },
      method: "GET",
      queryString: { tenant: "acme" },
      headers: { "x-client": { regex: "^cli/" } },
    },
    setHeaders: { Authorization: "Bearer t" },
  });
  assert.equal(wire.rules.length, 1);
  const match = wire.rules[0].match;
  assert.deepEqual(match.path, {
    op: "STRING_MATCH_OP_STARTS_WITH",
    value: "/repos/",
  });
  assert.deepEqual(match.methods, ["GET"]);
  assert.deepEqual(match.query, [
    { key: "tenant", value: { op: "STRING_MATCH_OP_EXACT", value: "acme" } },
  ]);
  assert.deepEqual(match.headers, [
    { key: "x-client", value: { op: "STRING_MATCH_OP_REGEX", value: "^cli/" } },
  ]);
  assert.deepEqual(wire.rules[0].setHeaders, {
    headers: [{ name: "Authorization", value: "Bearer t" }],
  });
});

test("a forward is carried onto the wire", () => {
  const wire = withRule({
    forward: { url: "http://gate.internal:8080/inspect", secret: "shared" },
  });
  assert.deepEqual(wire.rules[0].forward, {
    url: "http://gate.internal:8080/inspect",
    secret: "shared",
  });
  assert.equal(wire.rules[0].setHeaders, undefined);
});

// The scheme is the caller's choice between protecting the secret in transit
// and protecting it by where the endpoint sits, so both reach the wire.
test("an https forward url is accepted", () => {
  const wire = withRule({
    forward: { url: "https://gate.example.com/inspect", secret: "shared" },
  });
  assert.deepEqual(wire.rules[0].forward, {
    url: "https://gate.example.com/inspect",
    secret: "shared",
  });
});

// The same rules the node applies, refused where the caller can still read the
// policy that caused them.
test("a forward url that burrow would refuse is refused here", () => {
  for (const url of [
    "gate.internal",
    "ftp://gate.example.com/",
    "https://gate.example.com/x?a=1",
    "http://gate.internal/x#frag",
  ]) {
    assert.throws(
      () => withRule({ forward: { url } }),
      /forward url/,
      `${url} should be refused`,
    );
  }
});

// First match wins, so the order the caller wrote is the order that is sent.
test("a domain may carry several rules, narrowest first", () => {
  const wire = toNetworkPolicy({
    mode: "allowlist",
    allowDomains: ["api.github.com"],
    inspectTls: true,
    rules: [
      {
        domain: "api.github.com",
        match: { path: { startsWith: "/repos/" } },
        setHeaders: { Authorization: "Bearer narrow" },
      },
      { domain: "api.github.com", setHeaders: { Authorization: "Bearer wide" } },
    ],
  });
  assert.equal(wire.rules.length, 2);
  assert.ok(wire.rules[0].match);
  assert.equal(wire.rules[1].match, undefined);
});

test("a policy read back reports its rules", () => {
  const wire = toNetworkPolicy({
    mode: "allowlist",
    allowDomains: ["api.github.com"],
    inspectTls: true,
    rules: [
      {
        domain: "api.github.com",
        match: { path: { startsWith: "/repos/" } },
        setHeaders: { Authorization: "<redacted>" },
      },
      {
        domain: "api.github.com",
        forward: { url: "http://gate.internal/", secret: "<redacted>" },
      },
    ],
  });
  const read = fromNetworkPolicy(wire);
  assert.equal(read.rules.length, 2);
  assert.deepEqual(read.rules[0].match.path, { startsWith: "/repos/" });
  assert.equal(read.rules[1].forward.url, "http://gate.internal/");
});

test("a rule that sets headers and forwards at once is refused", () => {
  assert.throws(
    () =>
      withRule({
        forward: { url: "http://gate.internal/" },
        setHeaders: { A: "b" },
      }),
    (err) => {
      assert.equal(err.code, "invalid_argument");
      assert.match(err.message, /not both/);
      return true;
    },
  );
});

test("a match with no action is refused rather than silently dropped", () => {
  assert.throws(() => withRule({ match: { path: "/v1" } }), (err) => {
    assert.equal(err.code, "invalid_argument");
    assert.match(err.message, /setHeaders or forward/);
    return true;
  });
});

test("setHeaders naming no header is refused", () => {
  assert.throws(() => withRule({ setHeaders: {} }), /names no header/);
});

test("an unrecognised match dimension is refused by name", () => {
  assert.throws(
    () =>
      withRule({
        match: { paht: "/v1" },
        setHeaders: { A: "b" },
      }),
    (err) => {
      assert.equal(err.code, "invalid_argument");
      assert.match(err.message, /unknown key "paht" in a match/);
      return true;
    },
  );
});

test("any other unrecognised key is refused by name", () => {
  assert.throws(
    () => withRule({ setHeader: { A: "b" } }),
    (err) => {
      assert.equal(err.code, "invalid_argument");
      assert.match(err.message, /unknown key "setHeader"/);
      assert.match(err.message, /api\.github\.com/);
      return true;
    },
  );
});

// Rules act only on inspected requests, which means requests to an allowed
// domain; without one, nothing would ever reach them.
test("rules with no allowed domain are refused", () => {
  assert.throws(
    () =>
      toNetworkPolicy({
        mode: "allowlist",
        inspectTls: true,
        rules: [{ domain: "api.github.com", setHeaders: { A: "b" } }],
      }),
    /allowDomains/,
  );
});

test("a comparator nobody defined is refused", () => {
  assert.throws(
    () =>
      toNetworkPolicy({
        allowDomains: ["api.github.com"],
        rules: [
          {
            domain: "api.github.com",
            match: { path: { beginsWith: "/v1" } },
            setHeaders: { A: "b" },
          },
        ],
      }),
    (err) => {
      assert.equal(err.code, "invalid_argument");
      assert.match(err.message, /exact, startsWith or regex/);
      return true;
    },
  );
});

test("a network mode nobody defined is refused", () => {
  assert.throws(
    () => toNetworkPolicy({ mode: "allow-all" }),
    (err) => {
      assert.equal(err.code, "invalid_argument");
      assert.match(err.message, /unknown mode/);
      assert.match(err.message, /none, allowlist, open/);
      return true;
    },
  );
});

test("the three defined modes still pass", () => {
  assert.equal(toNetworkPolicy({ mode: "none" }).mode, "NETWORK_MODE_NONE");
  assert.equal(
    toNetworkPolicy({ mode: "allowlist" }).mode,
    "NETWORK_MODE_ALLOWLIST",
  );
  assert.equal(toNetworkPolicy({ mode: "open" }).mode, "NETWORK_MODE_OPEN");
  // Omitted is the documented default rather than an unknown mode.
  assert.equal(toNetworkPolicy().mode, "NETWORK_MODE_NONE");
});

test("denied ports and ipv6 reach the wire in open mode", () => {
  const wire = toNetworkPolicy({
    mode: "open",
    denyPorts: [
      { protocol: "tcp", port: 25 },
      { protocol: "tcp", port: 465, portEnd: 587 },
      { port: 5432, cidrs: ["10.0.0.0/8", "2001:db8::/32"] },
    ],
    denyIpv6: true,
  });
  assert.equal(wire.isIpv6Denied, true);
  assert.deepEqual(wire.denyPorts, [
    { protocol: "PORT_PROTOCOL_TCP", port: 25, portEnd: 0, cidrs: [] },
    { protocol: "PORT_PROTOCOL_TCP", port: 465, portEnd: 587, cidrs: [] },
    {
      protocol: "PORT_PROTOCOL_UNSPECIFIED",
      port: 5432,
      portEnd: 0,
      cidrs: ["10.0.0.0/8", "2001:db8::/32"],
    },
  ]);
});

test("the new fields default to what a policy meant before them", () => {
  const wire = toNetworkPolicy({ mode: "open" });
  assert.deepEqual(wire.denyPorts, []);
  assert.equal(wire.isIpv6Denied, false);
  const back = fromNetworkPolicy({ mode: "NETWORK_MODE_OPEN" });
  assert.deepEqual(back.denyPorts, []);
  assert.equal(back.denyIpv6, false);
});

test("a misspelt port rule is refused rather than widened", () => {
  for (const [rule, message] of [
    [{ protocol: "tpc", port: 25 }, /unknown protocol/],
    [{ port: 25, cidr: ["10.0.0.0/8"] }, /unknown key "cidr"/],
    [{ protocol: "tcp" }, /port is an integer/],
    [{ port: "25" }, /port is an integer/],
  ]) {
    assert.throws(
      () => toNetworkPolicy({ mode: "open", denyPorts: [rule] }),
      message,
    );
  }
});

test("port rules and ipv6 survive the real wire encoding", () => {
  // Through the generated codec, so a field name that does not exist in the
  // proto would be dropped here rather than by a node.
  const definition = protoLoader.loadSync("api.proto", {
    includeDirs: [fileURLToPath(new URL("../proto", import.meta.url))],
    keepCase: false,
    longs: Number,
    enums: String,
    defaults: true,
    oneofs: true,
  });
  const method = definition["burrow.api.v1.Burrow"].UpdateNetworkPolicy;
  const network = toNetworkPolicy({
    mode: "open",
    denyPorts: [
      { protocol: "tcp", port: 465, portEnd: 587 },
      { protocol: "udp", port: 53, cidrs: ["2001:db8::/32"] },
      { port: 25 },
    ],
    denyIpv6: true,
  });
  const decoded = method.requestDeserialize(
    method.requestSerialize({ network }),
  );
  const back = fromNetworkPolicy(decoded.network);
  assert.equal(back.mode, "open");
  assert.equal(back.denyIpv6, true);
  assert.deepEqual(back.denyPorts, [
    { protocol: "tcp", port: 465, portEnd: 587 },
    { protocol: "udp", port: 53, cidrs: ["2001:db8::/32"] },
    { port: 25 },
  ]);
});

test("an expiring rule in open mode is carried onto the wire and read back", () => {
  const expiresAt = new Date(Date.now() + 3_600_000);
  const wire = toNetworkPolicy({
    mode: "open",
    inspectTls: true,
    rules: [
      {
        domain: "api.example.com",
        match: { method: ["GET", "POST"] },
        setHeaders: { authorization: "Bearer ${secret:api}" },
        expiresAt,
      },
    ],
  });
  assert.equal(wire.mode, "NETWORK_MODE_OPEN");
  assert.equal(wire.isTlsInspected, true);
  assert.equal(wire.rules[0].expiresAtUnixMs, expiresAt.getTime());
  assert.equal(wire.rules[0].boundSandboxId, undefined);

  // What a node sends back: the rule bound to one sandbox.
  const read = fromNetworkPolicy({
    ...wire,
    rules: [
      {
        ...wire.rules[0],
        expiresAtUnixMs: String(expiresAt.getTime()),
        boundSandboxId: "sbx_a",
      },
    ],
  });
  assert.equal(read.rules[0].expiresAt.getTime(), expiresAt.getTime());
  assert.equal(read.rules[0].boundSandboxId, "sbx_a");
});

test("an expiry that is not a valid date is refused", () => {
  for (const expiresAt of [new Date(NaN), new Date(-1)]) {
    assert.throws(
      () => withRule({ setHeaders: { Authorization: "Bearer t" }, expiresAt }),
      /expiresAt/,
    );
  }
});
