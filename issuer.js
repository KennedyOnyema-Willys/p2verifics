import fs from 'fs';
import { bbs, utf8, hex, pickCiphersuiteString, generateIssuerKeyPair } from './utils.js';

async function main() {
  const ciphersuite = pickCiphersuiteString(bbs);

  const { secretKey, publicKey } = await generateIssuerKeyPair(ciphersuite);

  const messages = [
    utf8('subject=did:example:user456'),
    utf8('name=Kennedy'),
    utf8('age_over_18=true'),
    utf8('citizenship=NG'),
    utf8('student=UNT')
  ];

  const header = utf8('notary:did:example:notary123|schema:v1');

  const signature = await bbs.sign({
    secretKey,
    publicKey,
    header,
    messages,
    ciphersuite
  });

  const credential = {
    ciphersuite,
    issuerPublicKey: hex(publicKey),
    header: hex(header),
    messages: messages.map(hex),
    signature: hex(signature)
  };

  fs.writeFileSync('credential.json', JSON.stringify(credential, null, 2), 'utf8');
  console.log('Issuer: wrote credential.json');
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});