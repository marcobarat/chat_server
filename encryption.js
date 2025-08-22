import crypto from 'crypto';

// Derive a 32-byte key from the provided secret
const baseSecret = process.env.OWNER_PASS_KEY || 'insecure-default-key';
const DEFAULT_KEY = crypto.createHash('sha256').update(baseSecret).digest();

function getKey(secret) {
  return secret ? crypto.createHash('sha256').update(String(secret)).digest() : DEFAULT_KEY;
}

export function encrypt(plaintext, key = DEFAULT_KEY) {
  const iv = crypto.randomBytes(12); // AES-256-GCM standard IV length
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  // store as base64(iv|tag|ciphertext)
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}

export function decrypt(ciphertext, key = DEFAULT_KEY) {
  const data = Buffer.from(String(ciphertext), 'base64');
  const iv = data.subarray(0, 12);
  const tag = data.subarray(12, 28);
  const text = data.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(text), decipher.final()]);
  return decrypted.toString('utf8');
}

export { getKey };

