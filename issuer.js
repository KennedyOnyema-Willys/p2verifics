import fs from 'fs';
import { mkdir } from 'fs/promises';
import readline from 'readline/promises';
import { stdin as input, stdout as output } from 'process';

import {
  bbs, utf8, hex, pickCiphersuiteString, generateIssuerKeyPair,
  addOneYear, computeAgeYears
} from './utils.js';

function assertDobISO(dob) {
  // Expect YYYY-MM-DD
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dob)) {
    throw new Error('DOB must be in YYYY-MM-DD format.');
  }
  const d = new Date(dob + 'T00:00:00Z');
  if (Number.isNaN(d.getTime())) throw new Error('DOB is not a valid date.');
  return d.toISOString().slice(0, 10); // normalize to YYYY-MM-DD
}

async function main() {
  await mkdir('holder_store', { recursive: true });

  const rl = readline.createInterface({ input, output });

  const firstName = (await rl.question('First name: ')).trim();
  const lastName  = (await rl.question('Last name: ')).trim();
  const dobInput  = (await rl.question('DOB (YYYY-MM-DD): ')).trim();

  const street = (await rl.question('Street: ')).trim();
  const city   = (await rl.question('City: ')).trim();
  const state  = (await rl.question('State: ')).trim();
  const zip    = (await rl.question('Zip code: ')).trim();

  rl.close();

  const dob = assertDobISO(dobInput);

  const issueDate = new Date().toISOString();
  const expiryDate = addOneYear(issueDate);

  // Issuer computes these at issuance time (privacy-friendly: no DOB disclosure needed for 1A/1B)
  const ageNow = computeAgeYears(dob);
  const ageOver18 = ageNow >= 18;
  const ageOver21 = ageNow >= 21;

  const ciphersuite = pickCiphersuiteString(bbs);
  const { secretKey, publicKey } = await generateIssuerKeyPair(ciphersuite);

  // We model VC attributes as BBS "messages" (key=value). Each becomes selectively disclosable.
  const attrs = [
    ["subject", "did:example:user456"],
    ["first_name", firstName],
    ["last_name", lastName],
    ["dob", dob],
    ["addr_street", street],
    ["addr_city", city],
    ["addr_state", state],
    ["addr_zip", zip],
    ["issue", issueDate],
    ["expiry", expiryDate],
    ["age_over_18", String(ageOver18)],
    ["age_over_21", String(ageOver21)]
  ];

  const messages = attrs.map(([k, v]) => utf8(`${k}=${v}`));

  const header = utf8('issuer=did:example:notary123|schema=p2v-id-v1');

  const signature = await bbs.sign({
    secretKey,
    publicKey,
    header,
    messages,
    ciphersuite
  });

  // Save to holder device storage (demo: JSON file)
  const credential = {
    ciphersuite,
    issuerPublicKey: hex(publicKey),
    header: hex(header),

    // Keep attribute order and mapping so we can disclose by key later
    attributes: attrs.map(([k, v], i) => ({ index: i, key: k, value: v })),

    messages: messages.map(hex),
    signature: hex(signature)
  };

  fs.writeFileSync('holder_store/credential.json', JSON.stringify(credential, null, 2), 'utf8');
  console.log('\nIssuer: credential issued and saved to holder_store/credential.json');
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});