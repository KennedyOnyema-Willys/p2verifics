/**
 * benchmark.js
 * P2Verifics Performance Benchmark
 * Measures: keyGen, sign, deriveProof, verifyProof across all three policies
 * Run: node benchmark.js
 */

import * as bbs from '@digitalbazaar/bbs-signatures';
import crypto from 'crypto';

const enc = new TextEncoder();
const utf8  = (s) => enc.encode(s);
const hex   = (u8) => Buffer.from(u8).toString('hex');
const fromHex = (h) => new Uint8Array(Buffer.from(h, 'hex'));

// ── Config ────────────────────────────────────────────────────────────────────
const RUNS       = 100;   // iterations per operation
const CIPHERSUITE = 'BLS12-381-SHA-256';

// ── Helpers ───────────────────────────────────────────────────────────────────
function mean(arr)   { return arr.reduce((a,b) => a+b, 0) / arr.length; }
function stddev(arr) {
  const m = mean(arr);
  return Math.sqrt(arr.reduce((a,b) => a + (b-m)**2, 0) / arr.length);
}
function min(arr)    { return Math.min(...arr); }
function max(arr)    { return Math.max(...arr); }

function printTable(title, rows) {
  console.log(`\n${'─'.repeat(72)}`);
  console.log(` ${title}`);
  console.log(`${'─'.repeat(72)}`);
  console.log(
    ' Operation'.padEnd(30) +
    'Mean (ms)'.padStart(10) +
    'StdDev'.padStart(10) +
    'Min'.padStart(10) +
    'Max'.padStart(10)
  );
  console.log(`${'─'.repeat(72)}`);
  for (const r of rows) {
    console.log(
      ` ${r.name}`.padEnd(30) +
      r.mean.toFixed(3).padStart(10) +
      r.sd.toFixed(3).padStart(10) +
      r.min.toFixed(3).padStart(10) +
      r.max.toFixed(3).padStart(10)
    );
  }
  console.log(`${'─'.repeat(72)}`);
}

// ── Build credential attributes (same as issuer.js) ───────────────────────────
function buildAttrs() {
  const issueDate  = new Date().toISOString();
  const expiryDate = new Date(issueDate);
  expiryDate.setFullYear(expiryDate.getFullYear() + 1);

  return [
    ['subject',      'did:example:user456'],
    ['first_name',   'Alice'],
    ['last_name',    'Smith'],
    ['dob',          '1995-04-12'],
    ['addr_street',  '123 Main St'],
    ['addr_city',    'Springfield'],
    ['addr_state',   'IL'],
    ['addr_zip',     '62701'],
    ['issue',        issueDate],
    ['expiry',       expiryDate.toISOString()],
    ['age_over_18',  'true'],
    ['age_over_21',  'true'],
  ];
}

// ── Policy index sets (mirrors REQUEST_POLICIES in utils.js) ──────────────────
const POLICIES = {
  '1A': { label: 'Policy 1A (age≥18)',     indices: [0, 10, 9] },
  '1B': { label: 'Policy 1B (age≥21)',     indices: [0, 11, 9] },
  '2A': { label: 'Policy 2A (age+name)',   indices: [0,  1, 2, 3, 9] },
};

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  console.log('\nP2Verifics — BBS+ Performance Benchmark');
  console.log(`Ciphersuite : ${CIPHERSUITE}`);
  console.log(`Iterations  : ${RUNS} per operation`);
  console.log(`Node.js     : ${process.version}`);
  console.log(`Platform    : ${process.platform} ${process.arch}`);

  const attrs    = buildAttrs();
  const messages = attrs.map(([k,v]) => utf8(`${k}=${v}`));
  const header   = utf8('issuer=did:example:notary123|schema=p2v-id-v1');

  // ── 1. Key Generation ───────────────────────────────────────────────────────
  console.log('\n[1/4] Benchmarking key generation...');
  const keyGenTimes = [];
  let sk, pk;
  for (let i = 0; i < RUNS; i++) {
    const t0 = performance.now();
    const kp = await bbs.generateKeyPair({ ciphersuite: CIPHERSUITE });
    keyGenTimes.push(performance.now() - t0);
    if (i === RUNS - 1) { sk = kp.secretKey; pk = kp.publicKey; }
  }

  // ── 2. Signing (Issuance) ───────────────────────────────────────────────────
  console.log('[2/4] Benchmarking credential signing...');
  const signTimes = [];
  let signature;
  for (let i = 0; i < RUNS; i++) {
    const kp = await bbs.generateKeyPair({ ciphersuite: CIPHERSUITE });
    const t0 = performance.now();
    signature = await bbs.sign({
      secretKey: kp.secretKey,
      publicKey:  kp.publicKey,
      header, messages, ciphersuite: CIPHERSUITE
    });
    signTimes.push(performance.now() - t0);
    if (i === RUNS - 1) { sk = kp.secretKey; pk = kp.publicKey; }
  }

  // ── 3. Proof Derivation per policy ─────────────────────────────────────────
  console.log('[3/4] Benchmarking proof derivation per policy...');
  const deriveTimes = {};
  const proofSizes  = {};
  const proofs      = {};

  for (const [code, pol] of Object.entries(POLICIES)) {
    deriveTimes[code] = [];
    proofSizes[code]  = [];
    const nonce = crypto.randomBytes(16).toString('hex');
    const ph    = utf8(`nonce=${nonce}|org=BenchmarkOrg|code=${code}`);

    for (let i = 0; i < RUNS; i++) {
      const t0 = performance.now();
      const proof = await bbs.deriveProof({
        publicKey: pk, signature, header, messages,
        disclosedMessageIndexes: pol.indices,
        presentationHeader: ph,
        ciphersuite: CIPHERSUITE
      });
      deriveTimes[code].push(performance.now() - t0);
      proofSizes[code].push(proof.byteLength);
      if (i === RUNS - 1) proofs[code] = { proof, ph };
    }
  }

  // ── 4. Proof Verification per policy ───────────────────────────────────────
  console.log('[4/4] Benchmarking proof verification per policy...');
  const verifyTimes = {};

  for (const [code, pol] of Object.entries(POLICIES)) {
    verifyTimes[code] = [];
    const { proof, ph } = proofs[code];
    const disclosedMessages = pol.indices.map(i => messages[i]);

    for (let i = 0; i < RUNS; i++) {
      const t0 = performance.now();
      await bbs.verifyProof({
        publicKey: pk, proof, header,
        presentationHeader: ph,
        disclosedMessageIndexes: pol.indices,
        disclosedMessages,
        ciphersuite: CIPHERSUITE
      });
      verifyTimes[code].push(performance.now() - t0);
    }
  }

  // ── Results ─────────────────────────────────────────────────────────────────
  printTable('Key Generation & Signing', [
    { name: 'Key Generation',
      mean: mean(keyGenTimes), sd: stddev(keyGenTimes),
      min: min(keyGenTimes),   max: max(keyGenTimes) },
    { name: 'Credential Signing (12 msgs)',
      mean: mean(signTimes),   sd: stddev(signTimes),
      min: min(signTimes),     max: max(signTimes) },
  ]);

  const deriveRows = Object.entries(POLICIES).map(([code, pol]) => ({
    name: pol.label,
    mean: mean(deriveTimes[code]), sd: stddev(deriveTimes[code]),
    min:  min(deriveTimes[code]),  max: max(deriveTimes[code]),
  }));
  printTable('Proof Derivation (deriveProof)', deriveRows);

  const verifyRows = Object.entries(POLICIES).map(([code, pol]) => ({
    name: pol.label,
    mean: mean(verifyTimes[code]), sd: stddev(verifyTimes[code]),
    min:  min(verifyTimes[code]),  max: max(verifyTimes[code]),
  }));
  printTable('Proof Verification (verifyProof)', verifyRows);

  // Proof sizes
  console.log(`\n${'─'.repeat(72)}`);
  console.log(' Proof Sizes');
  console.log(`${'─'.repeat(72)}`);
  console.log(' Policy'.padEnd(30) + 'Mean (bytes)'.padStart(14) + 'Min'.padStart(8) + 'Max'.padStart(8));
  console.log(`${'─'.repeat(72)}`);
  for (const [code, pol] of Object.entries(POLICIES)) {
    const sizes = proofSizes[code];
    console.log(
      ` ${pol.label}`.padEnd(30) +
      mean(sizes).toFixed(1).padStart(14) +
      min(sizes).toString().padStart(8) +
      max(sizes).toString().padStart(8)
    );
  }
  console.log(`${'─'.repeat(72)}`);

  // Machine-readable CSV for LaTeX tables
  console.log('\n── CSV (copy into spreadsheet) ──────────────────────────────────────');
  console.log('operation,policy,mean_ms,sd_ms,min_ms,max_ms');
  console.log(`keyGen,N/A,${mean(keyGenTimes).toFixed(3)},${stddev(keyGenTimes).toFixed(3)},${min(keyGenTimes).toFixed(3)},${max(keyGenTimes).toFixed(3)}`);
  console.log(`sign,N/A,${mean(signTimes).toFixed(3)},${stddev(signTimes).toFixed(3)},${min(signTimes).toFixed(3)},${max(signTimes).toFixed(3)}`);
  for (const code of Object.keys(POLICIES)) {
    const d = deriveTimes[code], v = verifyTimes[code];
    console.log(`derive,${code},${mean(d).toFixed(3)},${stddev(d).toFixed(3)},${min(d).toFixed(3)},${max(d).toFixed(3)}`);
    console.log(`verify,${code},${mean(v).toFixed(3)},${stddev(v).toFixed(3)},${min(v).toFixed(3)},${max(v).toFixed(3)}`);
  }
  console.log(`proofSize,1A,${mean(proofSizes['1A']).toFixed(1)},N/A,${min(proofSizes['1A'])},${max(proofSizes['1A'])}`);
  console.log(`proofSize,1B,${mean(proofSizes['1B']).toFixed(1)},N/A,${min(proofSizes['1B'])},${max(proofSizes['1B'])}`);
  console.log(`proofSize,2A,${mean(proofSizes['2A']).toFixed(1)},N/A,${min(proofSizes['2A'])},${max(proofSizes['2A'])}`);
}

main().catch(e => { console.error(e); process.exit(1); });