import fs from 'fs';
import crypto from 'crypto';
import { bbs, fromHex, hex } from './utils.js';

async function main() {
  const credential = JSON.parse(fs.readFileSync('credential.json', 'utf8'));

  // Verifier should send a nonce; for demo we generate it here.
  // In a real flow: verifier -> holder sends nonce; holder uses that nonce below.
  const presentationHeader = crypto.randomBytes(16);

  const disclosedMessageIndexes = [0, 2]; // reveal subject + age_over_18

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
    proof: hex(proof)
  };

  fs.writeFileSync('presentation.json', JSON.stringify(presentation, null, 2), 'utf8');
  console.log('Holder: wrote presentation.json');
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});