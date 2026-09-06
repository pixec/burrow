import { Sandbox } from "./dist/index.js";
const opts = { apiKey: "dev-token", endpoint: "localhost:7070", timeoutMs: 120000 };
const ms = async (f) => { const s = process.hrtime.bigint(); const r = await f(); return [Number(process.hrtime.bigint() - s) / 1e6, r]; };
// Nearest-rank: the p-th quantile of n samples is the ceil(p*n)-th of them,
// so q(...,0.9) over 12 samples is the 11th and not the 10th.
const q = (r, p) => { const s = [...r].sort((a,b)=>a-b); return s[Math.min(s.length - 1, Math.max(0, Math.ceil(p * s.length) - 1))]; };
const r = [];
for (let i = 0; i < 12; i++) {
  const [t, sb] = await ms(() => Sandbox.create(opts));
  r.push(t);
  try {
    // Prove it is a working sandbox, not just a fast reply.
    const out = await sb.exec("echo alive");
    if (out.stdout.trim() !== "alive") throw new Error("pooled sandbox not usable");
  } finally {
    // Whatever went wrong, the VM is still running until this call: without
    // the finally a single failed run leaks a sandbox per iteration.
    await sb.kill();
  }
  await new Promise((res) => setTimeout(res, 400)); // let the pool refill
}
console.log(`  create  n=${r.length}  min ${q(r,0).toFixed(0)}  p50 ${q(r,.5).toFixed(0)}  p90 ${q(r,.9).toFixed(0)}ms`);
console.log(`  each: ${r.map(x => x.toFixed(0)).join(", ")}`);
