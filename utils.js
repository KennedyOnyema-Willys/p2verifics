import * as bbs from '@digitalbazaar/bbs-signatures';

const enc = new TextEncoder();
export const utf8 = (s) => enc.encode(s);
export const hex = (u8) => Buffer.from(u8).toString('hex');
export const fromHex = (h) => new Uint8Array(Buffer.from(h, 'hex'));
export const toUtf8String = (hexStr) => Buffer.from(hexStr, 'hex').toString('utf8');

export function pickCiphersuiteString(mod = bbs) {
  if (mod.ciphersuites && typeof mod.ciphersuites === 'object') {
    const keys = Object.keys(mod.ciphersuites);
    const preferred =
      keys.find(k => k.toLowerCase().includes('bls') && k.toLowerCase().includes('sha')) ||
      keys[0];
    return preferred;
  }
  return 'BLS12-381-SHA-256';
}

export async function generateIssuerKeyPair(ciphersuite) {
  try {
    return await bbs.generateKeyPair({ ciphersuite });
  } catch {
    return await bbs.generateKeyPair();
  }
}

export { bbs };