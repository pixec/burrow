// Rules a JavaScript caller can write that TypeScript would have refused, and
// the shapes the SDK maps onto burrow's own.
//
// The SDK's own examples are .mjs, so excess-property checking is not the last
// line of defence here: these keys have to be handled at runtime too.

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  fromNetworkPolicy,
  resolveNetwork,
  toNetworkPolicy,
} from "../dist/policy.js";

/** The narrowest policy that carries a per-domain rule. */
function withRule(rule) {
  return resolveNetwork({
    allow: { "api.github.com": rule },
    inspectTls: true,
  });
}

test("a rule with only a transform is accepted", () => {
  const policy = withRule({
    transform: [{ headers: { Authorization: "Bearer t" } }],
  });
  assert.deepEqual(policy.rules, [
    {
      domain: "api.github.com",
      match: undefined,
      setHeaders: { Authorization: "Bearer t" },
    },
  ]);
  assert.equal(policy.inspectTls, true);
});

// A matcher selects which requests the rule acts on. It never blocks: a
// request matching nothing is still allowed, it just goes unmodified.
test("a request matcher is carried onto the wire", () => {
  const policy = withRule({
    match: {
      path: { startsWith: "/repos/" },
      method: "GET",
      queryString: { tenant: "acme" },
      headers: { "x-client": { regex: "^cli/" } },
    },
    transform: [{ headers: { Authorization: "Bearer t" } }],
  });
  const wire = toNetworkPolicy(policy);
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

test("forwardURL becomes a forward action", () => {
  const policy = withRule({
    forwardURL: "http://gate.internal:8080/inspect",
    forwardSecret: "shared",
  });
  const wire = toNetworkPolicy(policy);
  assert.deepEqual(wire.rules[0].forward, {
    url: "http://gate.internal:8080/inspect",
    secret: "shared",
  });
  assert.equal(wire.rules[0].setHeaders, undefined);
});

// The scheme is the caller's choice between protecting the secret in transit
// and protecting it by where the endpoint sits, so both reach the wire.
test("an https forward url is accepted", () => {
  const wire = toNetworkPolicy(
    withRule({
      forwardURL: "https://gate.example.com/inspect",
      forwardSecret: "shared",
    }),
  );
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
      () => toNetworkPolicy(withRule({ forwardURL: url })),
      /forward url/,
      `${url} should be refused`,
    );
  }
});

// First match wins, so the order the caller wrote is the order that is sent.
test("a domain may carry several rules, narrowest first", () => {
  const policy = resolveNetwork({
    allow: {
      "api.github.com": [
        {
          match: { path: { startsWith: "/repos/" } },
          transform: [{ headers: { Authorization: "Bearer narrow" } }],
        },
        { transform: [{ headers: { Authorization: "Bearer wide" } }] },
      ],
    },
  });
  assert.equal(policy.rules.length, 2);
  assert.ok(policy.rules[0].match);
  assert.equal(policy.rules[1].match, undefined);
});

test("injectHeaders are appended after rules", () => {
  const wire = toNetworkPolicy({
    rules: [
      {
        domain: "api.github.com",
        match: { path: "/v1" },
        setHeaders: { "X-Narrow": "n" },
      },
    ],
    injectHeaders: [
      { domain: "api.github.com", name: "X-Wide", value: "w" },
    ],
  });
  assert.deepEqual(
    wire.rules.map((rule) => rule.setHeaders.headers[0].name),
    ["X-Narrow", "X-Wide"],
  );
});

test("a policy read back reports rules, and injections among them", () => {
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
    injectHeaders: [{ domain: "api.github.com", name: "X-Key", value: "k" }],
  });
  const read = fromNetworkPolicy(wire);
  assert.equal(read.rules.length, 3);
  assert.deepEqual(read.rules[0].match.path, { startsWith: "/repos/" });
  assert.equal(read.rules[1].forward.url, "http://gate.internal/");
  // Only the matcher-less header rules read back as injections.
  assert.deepEqual(read.injectHeaders, [
    { domain: "api.github.com", name: "X-Key", value: "k" },
  ]);
});

test("a rule that rewrites and forwards at once is refused", () => {
  assert.throws(
    () =>
      withRule({
        forwardURL: "http://gate.internal/",
        transform: [{ headers: { A: "b" } }],
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
    assert.match(err.message, /transform or a forwardURL/);
    return true;
  });
});

test("an unrecognised match dimension is refused by name", () => {
  assert.throws(
    () =>
      withRule({
        match: { paht: "/v1" },
        transform: [{ headers: { A: "b" } }],
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
    () => withRule({ tranfsorm: [{ headers: { A: "b" } }] }),
    (err) => {
      assert.equal(err.code, "invalid_argument");
      assert.match(err.message, /unknown key "tranfsorm"/);
      assert.match(err.message, /api\.github\.com/);
      return true;
    },
  );
});

test("a comparator nobody defined is refused", () => {
  assert.throws(
    () =>
      toNetworkPolicy({
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
