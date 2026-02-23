import fs from 'fs';
import { bbs, fromHex, REQUEST_POLICIES, toUtf8String, randomNonceHex } from './utils.js';

function usage() {
  console.log('Usage:');
  console.log('  node verifier.js request <CODE> "<ORG_NAME>"');
  console.log('  node verifier.js verify "<ORG_NAME>"');
  process.exit(1);
}

function keyFromMessageString(msg) {
  const s = msg.includes('=') ? msg.split('=')[0] : '';
  return s;
}

async function main() {
  const mode = process.argv[2];
  if (!mode) usage();

  if (mode === 'request') {
    const code = process.argv[3];
    const orgName = process.argv[4] || 'Verifier';

    const policy = REQUEST_POLICIES[code];
    if (!policy) {
      console.error(`Unknown code ${code}. Use one of: ${Object.keys(REQUEST_POLICIES).join(', ')}`);
      process.exit(1);
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
    return;
  }

  if (mode === 'verify') {
    const orgName = process.argv[3] || 'Verifier';

    if (!fs.existsSync('presentation.json')) {
      console.error('Missing presentation.json. Holder must create it first.');
      process.exit(1);
    }

    const presentation = JSON.parse(fs.readFileSync('presentation.json', 'utf8'));

    // Verify signature proof OFFLINE
    const proofOk = await bbs.verifyProof({
      publicKey: fromHex(presentation.issuerPublicKey),
      proof: fromHex(presentation.proof),
      header: fromHex(presentation.header),
      presentationHeader: fromHex(presentation.presentationHeader),
      disclosedMessageIndexes: presentation.disclosedMessageIndexes,
      disclosedMessages: presentation.disclosedMessages.map(fromHex),
      ciphersuite: presentation.ciphersuite
    });

    // Parse disclosed messages -> map keys/values
    const disclosed = presentation.disclosedMessages.map(toUtf8String);
    const disclosedMap = {};
    for (const kv of disclosed) {
      const [k, ...rest] = kv.split('=');
      disclosedMap[k] = rest.join('=');
    }

    // Expiry check (must have expiry disclosed in all our policies)
    let expiryOk = false;
    if (disclosedMap.expiry) {
      const exp = new Date(disclosedMap.expiry);
      expiryOk = !Number.isNaN(exp.getTime()) && exp.getTime() > Date.now();
    }

    const valid = Boolean(proofOk && expiryOk);

    // For 2A: verifier can compute age if dob disclosed
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
    return;
  }

  usage();
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});