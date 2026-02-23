import fs from 'fs';
import readline from 'readline/promises';
import { stdin as input, stdout as output } from 'process';

import {
  bbs, fromHex, hex, utf8,
  REQUEST_POLICIES
} from './utils.js';

function usageAndExit(msg) {
  if (msg) console.error(msg);
  console.error('Need request.json and holder_store/credential.json');
  process.exit(1);
}

function buildKeyIndexMap(credential) {
  const map = {};
  for (const a of credential.attributes) map[a.key] = a.index;
  return map;
}

export async function createPresentationInteractive(rlArg) {
  if (!fs.existsSync('request.json')) usageAndExit('Missing request.json. Verifier must create a request first.');
  if (!fs.existsSync('holder_store/credential.json')) usageAndExit('Missing holder_store/credential.json. Issuer must issue first.');

  const request = JSON.parse(fs.readFileSync('request.json', 'utf8'));
  const credential = JSON.parse(fs.readFileSync('holder_store/credential.json', 'utf8'));

  const policy = REQUEST_POLICIES[request.code];
  if (!policy) usageAndExit(`Unknown request code in request.json: ${request.code}`);

  console.log('\n--- Holder Consent ---');
  console.log(`${request.orgName} is requesting to ${policy.description}.`);
  console.log(`Request code: ${request.code}`);
  console.log('Data that would be shared:');
  for (const k of policy.discloseKeys) console.log(`  - ${k}`);

  const rl = rlArg ?? readline.createInterface({ input, output });
  const ans = (await rl.question('\nDo you agree to share? (y/n): ')).trim().toLowerCase();
  if (!rlArg) rl.close();

  if (ans !== 'y' && ans !== 'yes') {
    console.log('Holder: declined. No presentation created.');
    if (fs.existsSync('presentation.json')) fs.unlinkSync('presentation.json');
    return null;
  }

  const keyIndex = buildKeyIndexMap(credential);
  const disclosedMessageIndexes = policy.discloseKeys.map(k => {
    if (keyIndex[k] === undefined) throw new Error(`Credential missing attribute key: ${k}`);
    return keyIndex[k];
  }).sort((a, b) => a - b);

  const presentationHeader = utf8(`nonce=${request.nonceHex}|org=${request.orgName}|code=${request.code}`);

  const proof = await bbs.deriveProof({
    publicKey: fromHex(credential.issuerPublicKey),
    signature: fromHex(credential.signature),
    header: fromHex(credential.header),
    messages: credential.messages.map(fromHex),
    disclosedMessageIndexes,
    presentationHeader,
    ciphersuite: credential.ciphersuite
  });

  const disclosedMessages = disclosedMessageIndexes.map(i => credential.messages[i]);

  const presentation = {
    ciphersuite: credential.ciphersuite,
    issuerPublicKey: credential.issuerPublicKey,
    header: credential.header,
    disclosedMessageIndexes,
    disclosedMessages,
    presentationHeader: hex(presentationHeader),
    proof: hex(proof),
    request: {
      orgName: request.orgName,
      code: request.code,
      description: request.description,
      nonceHex: request.nonceHex,
      requestedAt: request.requestedAt
    }
  };

  fs.writeFileSync('presentation.json', JSON.stringify(presentation, null, 2), 'utf8');
  console.log('\nHolder: shared presentation.json');
  console.log('Next: verifier should run verification.');

  return presentation;
}

// Keep CLI support
async function main() {
  await createPresentationInteractive();
}

if (import.meta.url === new URL(process.argv[1], 'file:').href) {
  main().catch(e => {
    console.error(e);
    process.exit(1);
  });
}
