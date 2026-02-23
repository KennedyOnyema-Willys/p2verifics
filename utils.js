import * as bbs from '@digitalbazaar/bbs-signatures';
import crypto from 'crypto';

export { bbs };

export const enc = new TextEncoder();
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

export function addOneYear(isoDateString) {
  const d = new Date(isoDateString);
  d.setFullYear(d.getFullYear() + 1);
  return d.toISOString();
}

export function computeAgeYears(dobISO, now = new Date()) {
  const dob = new Date(dobISO);
  let age = now.getFullYear() - dob.getFullYear();
  const m = now.getMonth() - dob.getMonth();
  if (m < 0 || (m === 0 && now.getDate() < dob.getDate())) age--;
  return age;
}

export function randomNonceHex(bytes = 16) {
  return crypto.randomBytes(bytes).toString('hex');
}

/**
 * Request codes -> human meaning + which attributes holder should disclose
 * We disclose signed boolean flags for 1A/1B, and name + DOB for 2A.
 */
export const REQUEST_POLICIES = {
  "1A": {
    description: "validate that age is over 18",
    discloseKeys: ["subject", "age_over_18", "expiry"]
  },
  "1B": {
    description: "validate that age is over 21",
    discloseKeys: ["subject", "age_over_21", "expiry"]
  },
  "2A": {
    description: "validate age and name",
    discloseKeys: ["subject", "first_name", "last_name", "dob", "expiry"]
  }
};