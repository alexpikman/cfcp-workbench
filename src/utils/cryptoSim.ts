// Cryptographic utilities and ChaCha20-Poly1305 AEAD simulation

// Compute real SHA-256 hash using the Web Crypto API
export async function sha256Digest(data: string | Uint8Array): Promise<string> {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes as unknown as BufferSource);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Convert byte array to hexadecimal string
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// Convert hex string to byte array
export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// Generate deterministic 96-bit (12-byte) nonce:
// [0:8] MessageID (64-bit BigEndian hex)
// [8:12] FragmentIndex (32-bit BigEndian hex)
export function deriveDeterministicNonce(messageIdHex: string, fragmentIndex: number): string {
  // Normalize message ID to 16 hex chars (8 bytes)
  const cleanMsgId = messageIdHex.replace(/^0x/, '').padStart(16, '0').slice(0, 16);
  // Fragment index to 8 hex chars (4 bytes)
  const fragIdxHex = fragmentIndex.toString(16).padStart(8, '0');
  return cleanMsgId + fragIdxHex;
}

// Generate random 64-bit Message ID in hex
export function generateRandomMessageId(): string {
  const buf = new Uint8Array(8);
  crypto.getRandomValues(buf);
  return bytesToHex(buf);
}

// Authenticated Encryption (ChaCha20-Poly1305 Simulation)
// Creates authentic ciphertext with attached 16-byte Poly1305 tag
export async function simulateAEADEncrypt(
  plaintext: string,
  nonceHex: string,
  aadHex: string,
  pskHex: string
): Promise<{ ciphertextHex: string; poly1305TagHex: string }> {
  const plainBytes = new TextEncoder().encode(plaintext);
  const nonceBytes = hexToBytes(nonceHex);
  const pskBytes = hexToBytes(pskHex.slice(0, 64).padEnd(64, '0'));

  // ChaCha20 stream keystream simulation using deterministic hashing of PSK + Nonce
  const seedString = `${bytesToHex(pskBytes)}:${bytesToHex(nonceBytes)}`;
  const keyStreamHash = await sha256Digest(seedString);
  const keyStreamBytes = hexToBytes(keyStreamHash);

  const cipherBytes = new Uint8Array(plainBytes.length);
  for (let i = 0; i < plainBytes.length; i++) {
    cipherBytes[i] = plainBytes[i] ^ keyStreamBytes[i % keyStreamBytes.length];
  }

  // Poly1305 Authenticator over AAD + Ciphertext + Nonce
  const macInput = `${aadHex}:${bytesToHex(cipherBytes)}:${nonceHex}:${pskHex}`;
  const macFullHash = await sha256Digest(macInput);
  const poly1305TagHex = macFullHash.slice(0, 32); // 16 bytes = 32 hex chars

  return {
    ciphertextHex: bytesToHex(cipherBytes),
    poly1305TagHex,
  };
}

// Authenticated Decryption (ChaCha20-Poly1305 Simulation)
// Validates Poly1305 MAC tag and decrypts ciphertext
export async function simulateAEADDecrypt(
  ciphertextHex: string,
  poly1305TagHex: string,
  nonceHex: string,
  aadHex: string,
  pskHex: string
): Promise<{ success: boolean; plaintext?: string; error?: string }> {
  const pskBytes = hexToBytes(pskHex.slice(0, 64).padEnd(64, '0'));
  const nonceBytes = hexToBytes(nonceHex);

  // Recompute expected Poly1305 MAC tag
  const macInput = `${aadHex}:${ciphertextHex}:${nonceHex}:${pskHex}`;
  const expectedMacFullHash = await sha256Digest(macInput);
  const expectedTagHex = expectedMacFullHash.slice(0, 32);

  // Authenticate
  if (expectedTagHex.toLowerCase() !== poly1305TagHex.toLowerCase()) {
    return {
      success: false,
      error: 'Poly1305 MAC authentication failed (tampered ciphertext, forged header AAD, or wrong key)',
    };
  }

  // Decrypt
  const cipherBytes = hexToBytes(ciphertextHex);
  const seedString = `${bytesToHex(pskBytes)}:${bytesToHex(nonceBytes)}`;
  const keyStreamHash = await sha256Digest(seedString);
  const keyStreamBytes = hexToBytes(keyStreamHash);

  const plainBytes = new Uint8Array(cipherBytes.length);
  for (let i = 0; i < cipherBytes.length; i++) {
    plainBytes[i] = cipherBytes[i] ^ keyStreamBytes[i % keyStreamBytes.length];
  }

  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(plainBytes);
    return { success: true, plaintext: text };
  } catch {
    return { success: false, error: 'Decrypted bytes are not valid UTF-8' };
  }
}
