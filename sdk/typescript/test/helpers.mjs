// Handles over a fake transport, for tests that never touch the network.

import { Burrow } from "../dist/client.js";
import { Sandbox, toSandboxInfo } from "../dist/sandbox.js";

/** A running sandbox `sbx_test` whose calls go to `transport`. */
export function fakeSandbox(transport, raw = {}) {
  return new Sandbox(transport, toSandboxInfo({ id: "sbx_test", state: "SANDBOX_STATE_RUNNING", ...raw }));
}

/** A client whose fleet calls go to `transport`. */
export function fakeBurrow(transport) {
  const burrow = new Burrow({ endpoint: "localhost:1" });
  burrow.close();
  burrow.transport = transport;
  return burrow;
}
