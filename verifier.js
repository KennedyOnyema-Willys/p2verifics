import fs from 'fs';
import { bbs, fromHex, toUtf8String } from './utils.js';

async function main() {
  const presentation = JSON.parse(fs.readFileSync('presentation.json', 'utf8'));

  const verified = await bbs.verifyProof({
    publicKey: fromHex(presentation.issuerPublicKey),
    proof: fromHex(presentation.proof),
    header: fromHex(presentation.header),
    presentationHeader: fromHex(presentation.presentationHeader),
    disclosedMessageIndexes: presentation.disclosedMessageIndexes,
    disclosedMessages: presentation.disclosedMessages.map(fromHex),
    ciphersuite: presentation.ciphersuite
  });

  console.log('Verified:', verified);

  if (verified) {
    console.log('GREEN: Accept credential');
    console.log('Disclosed:', presentation.disclosedMessages.map(toUtf8String));
  } else {
    console.log('RED: Reject credential');
  }
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});