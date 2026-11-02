// Strict base64url (RFC 4648 section 5), NO padding. Pure TS, no native imports.
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const LOOKUP: Record<string, number> = {};
for (let i = 0; i < ALPHABET.length; i++) LOOKUP[ALPHABET.charAt(i)] = i;

export function base64UrlEncode(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]! + ALPHABET[(n >> 6) & 63]! + ALPHABET[n & 63]!;
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i]! << 16;
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]!;
  } else if (rest === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]! + ALPHABET[(n >> 6) & 63]!;
  }
  return out;
}

/** Rejects '=', '+', '/', whitespace, any non-alphabet char, impossible lengths (len % 4 === 1) and non-zero trailing bits. */
export function base64UrlDecode(input: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(input)) throw new Error('invalid base64url');
  if (input.length % 4 === 1) throw new Error('invalid base64url length');
  const out = new Uint8Array(Math.floor((input.length * 3) / 4));
  let o = 0;
  let i = 0;
  for (; i + 3 < input.length; i += 4) {
    const n =
      (LOOKUP[input.charAt(i)]! << 18) | (LOOKUP[input.charAt(i + 1)]! << 12) | (LOOKUP[input.charAt(i + 2)]! << 6) | LOOKUP[input.charAt(i + 3)]!;
    out[o++] = (n >> 16) & 255;
    out[o++] = (n >> 8) & 255;
    out[o++] = n & 255;
  }
  const rest = input.length - i;
  if (rest === 2) {
    const n = (LOOKUP[input.charAt(i)]! << 18) | (LOOKUP[input.charAt(i + 1)]! << 12);
    if ((n & 0xffff) !== 0) throw new Error('non-canonical base64url');
    out[o++] = (n >> 16) & 255;
  } else if (rest === 3) {
    const n = (LOOKUP[input.charAt(i)]! << 18) | (LOOKUP[input.charAt(i + 1)]! << 12) | (LOOKUP[input.charAt(i + 2)]! << 6);
    if ((n & 0xff) !== 0) throw new Error('non-canonical base64url');
    out[o++] = (n >> 16) & 255;
    out[o++] = (n >> 8) & 255;
  }
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) throw new Error('invalid hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
