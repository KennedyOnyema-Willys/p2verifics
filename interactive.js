import fs from 'fs';
import path from 'path';
import readline from 'readline/promises';
import { stdin as input, stdout as output } from 'process';

import { issueCredentialInteractive } from './issuer.js';
import { createPresentationInteractive } from './holder.js';
import { createRequest, verifyPresentation } from './verifier.js';
import { REQUEST_POLICIES } from './utils.js';

const FILES = {
  holderCredential: path.join('holder_store', 'credential.json'),
  request: 'request.json',
  presentation: 'presentation.json',
  verification: 'verification_result.json'
};

function exists(p) {
  return fs.existsSync(p);
}

function readJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function safeUnlink(p) {
  if (exists(p)) fs.unlinkSync(p);
}

function printStatus() {
  console.log('\n--- Status ---');
  console.log(`Holder credential:   ${exists(FILES.holderCredential) ? '✅' : '❌'} (${FILES.holderCredential})`);
  console.log(`Verifier request:    ${exists(FILES.request) ? '✅' : '❌'} (${FILES.request})`);
  console.log(`Presentation:        ${exists(FILES.presentation) ? '✅' : '❌'} (${FILES.presentation})`);
  console.log(`Verification result: ${exists(FILES.verification) ? '✅' : '❌'} (${FILES.verification})`);

  if (exists(FILES.request)) {
    const r = readJson(FILES.request);
    console.log(`Last request: code=${r.code}, org=${r.orgName}`);
  }
  if (exists(FILES.verification)) {
    const v = readJson(FILES.verification);
    console.log(`Last verify: valid=${v.valid}, proofOk=${v.verifiedProof}, notExpired=${v.notExpired}`);
  }
}

async function chooseRequest(rl) {
  const orgName = (await rl.question('Verifier org name (default: E-Corp): ')).trim() || 'E-Corp';
  let code = (await rl.question('Request code (1A, 1B, 2A): ')).trim().toUpperCase();

  while (!REQUEST_POLICIES[code]) {
    code = (await rl.question(`Invalid. Choose ${Object.keys(REQUEST_POLICIES).join(', ')}: `)).trim().toUpperCase();
  }

  console.log(`\n${orgName} is requesting to ${REQUEST_POLICIES[code].description}.`);
  console.log('Fields requested:');
  for (const k of REQUEST_POLICIES[code].discloseKeys) console.log(`  - ${k}`);

  return { code, orgName };
}

async function viewFileMenu(rl) {
  console.log('\n--- View Files ---');
  console.log('1) holder_store/credential.json');
  console.log('2) request.json');
  console.log('3) presentation.json');
  console.log('4) verification_result.json');
  console.log('0) back');

  const c = (await rl.question('Choose: ')).trim();

  let p = null;
  if (c === '1') p = FILES.holderCredential;
  if (c === '2') p = FILES.request;
  if (c === '3') p = FILES.presentation;
  if (c === '4') p = FILES.verification;
  if (c === '0') return;

  if (!p) return console.log('Invalid.');
  if (!exists(p)) return console.log(`Missing: ${p}`);

  console.log(`\n--- ${p} ---`);
  console.log(fs.readFileSync(p, 'utf8'));
}

async function main() {
  const rl = readline.createInterface({ input, output });

  while (true) {
    printStatus();

    console.log('\n=== P2Verifics (Single Runner) ===');
    console.log('1) Issue ID (Issuer enters details)');
    console.log('2) Verifier creates request (1A / 1B / 2A)');
    console.log('3) Holder responds (consent + create presentation)');
    console.log('4) Verifier verifies offline');
    console.log('5) Full flow (Issue -> Request -> Holder -> Verify)');
    console.log('6) View JSON files');
    console.log('7) Reset session files (request/presentation/verification)');
    console.log('0) Exit');

    const choice = (await rl.question('\nSelect: ')).trim();

    try {
      if (choice === '1') {
        await issueCredentialInteractive(rl);
      } else if (choice === '2') {
        const { code, orgName } = await chooseRequest(rl);
        await createRequest(code, orgName);
      } else if (choice === '3') {
        if (!exists(FILES.request)) {
          console.log('Missing request.json. Run option 2 first.');
          continue;
        }
        if (!exists(FILES.holderCredential)) {
          console.log('Missing holder_store/credential.json. Run option 1 first.');
          continue;
        }
        await createPresentationInteractive(rl);
      } else if (choice === '4') {
        if (!exists(FILES.presentation)) {
          console.log('Missing presentation.json. Run option 3 first.');
          continue;
        }
        const orgName = exists(FILES.request) ? readJson(FILES.request).orgName : 'Verifier';
        await verifyPresentation(orgName);
      } else if (choice === '5') {
        console.log('\n--- Issue ---');
        await issueCredentialInteractive(rl);

        console.log('\n--- Request ---');
        const { code, orgName } = await chooseRequest(rl);
        await createRequest(code, orgName);

        console.log('\n--- Holder Consent ---');
        const pres = await createPresentationInteractive(rl);
        if (!pres) {
          console.log('\nHolder declined. Stopping.');
          continue;
        }

        console.log('\n--- Verify ---');
        await verifyPresentation(orgName);
      } else if (choice === '6') {
        await viewFileMenu(rl);
      } else if (choice === '7') {
        safeUnlink(FILES.request);
        safeUnlink(FILES.presentation);
        safeUnlink(FILES.verification);
        console.log('Reset done (credential kept).');
      } else if (choice === '0') {
        break;
      } else {
        console.log('Invalid option.');
      }
    } catch (e) {
      console.error('\nError:', e?.message ?? e);
    }
  }

  rl.close();
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});
