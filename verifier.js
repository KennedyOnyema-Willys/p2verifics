import fs from 'fs';
import { bbs, fromHex, REQUEST_POLICIES, toUtf8String, randomNonceHex } from './utils.js';

function usage() {
  console.log('Usage:');
  console.log('  node verifier.js request <CODE> "<ORG_NAME>"');
  console.log('  node verifier.js verify "<ORG_NAME>"');
  process.exit(1);
}

export async function createRequest(code, orgName = 'Verifier') {
  const policy = REQUEST_POLICIES[code];
  if (!policy) {
    throw new Error(`Unknown code ${code}. Use one of: ${Object.keys(REQUEST_POLICIES).join(', ')}`);
  }

  const req = {
    orgName,
    code,
    description: policy.description,
    nonceHex: randomNonceHex(16),
    requestedAt: new Date().toISOString()
  };

  fs.writeFileSync('request.json', JSON.stringify(req, null, 2), 'utf8');
  console.log(`Verifier: wrote request.json (${code} - ${policy.description})`);
  return req;
}

export async function verifyPresentation(orgName = 'Verifier') {
  if (!fs.existsSync('presentation.json')) {
    throw new Error('Missing presentation.json. Holder must create it first.');
  }

  const presentation = JSON.parse(fs.readFileSync('presentation.json', 'utf8'));

  const proofOk = await bbs.verifyProof({
    publicKey: fromHex(presentation.issuerPublicKey),
    proof: fromHex(presentation.proof),
    header: fromHex(presentation.header),
    presentationHeader: fromHex(presentation.presentationHeader),
    disclosedMessageIndexes: presentation.disclosedMessageIndexes,
    disclosedMessages: presentation.disclosedMessages.map(fromHex),
    ciphersuite: presentation.ciphersuite
  });

  const disclosed = presentation.disclosedMessages.map(toUtf8String);
  const disclosedMap = {};
  for (const kv of disclosed) {
    const [k, ...rest] = kv.split('=');
    disclosedMap[k] = rest.join('=');
  }

  let expiryOk = false;
  if (disclosedMap.expiry) {
    const exp = new Date(disclosedMap.expiry);
    expiryOk = !Number.isNaN(exp.getTime()) && exp.getTime() > Date.now();
  }

  const valid = Boolean(proofOk && expiryOk);

  let computedAge = null;
  if (disclosedMap.dob) {
    const dob = new Date(disclosedMap.dob + 'T00:00:00Z');
    if (!Number.isNaN(dob.getTime())) {
      const now = new Date();
      let age = now.getFullYear() - dob.getFullYear();
      const m = now.getMonth() - dob.getMonth();
      if (m < 0 || (m === 0 && now.getDate() < dob.getDate())) age--;
      computedAge = age;
    }
  }

  const result = {
    orgName,
    verifiedProof: proofOk,
    notExpired: expiryOk,
    valid,
    disclosed,
    computedAge
  };

  fs.writeFileSync('verification_result.json', JSON.stringify(result, null, 2), 'utf8');

  console.log('Verifier:', valid ? 'GREEN (valid)' : 'RED (invalid)');
  console.log('Wrote verification_result.json');

  return result;
}

// Keep CLI support
async function main() {
  const mode = process.argv[2];
  if (!mode) usage();

  if (mode === 'request') {
    const code = process.argv[3];
    const orgName = process.argv[4] || 'Verifier';
    await createRequest(code, orgName);
    return;
  }

  if (mode === 'verify') {
    const orgName = process.argv[3] || 'Verifier';
    await verifyPresentation(orgName);
    return;
  }

  usage();
}

if (import.meta.url === new URL(process.argv[1], 'file:').href) {
  main().catch(e => {
    console.error(e);
    process.exit(1);
  });
}