/**
 * ECC (Elliptic Curve Cryptography) utilities for secure key generation and ECDH key exchange
 * Uses Web Crypto API for all cryptographic operations
 * Implements ECDH key exchange with P-384 curve for enhanced security
 */

// ECC curve parameters - using P-384 for better security
const ECC_CURVE = 'P-384';
const KEY_FORMAT = 'raw';

/**
 * Generate ECC key pair for long-term user identity
 * @returns {Promise<{publicKey: CryptoKey, privateKey: CryptoKey}>}
 */
export async function generateECCKeyPair() {
  try {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: ECC_CURVE,
      },
      true, // extractable
      ['deriveKey', 'deriveBits']
    );
    return keyPair;
  } catch (error) {
    console.error('Failed to generate ECC key pair:', error);
    throw new Error('Key generation failed');
  }
}

/**
 * Generate ephemeral ECC key pair for session key exchange
 * @returns {Promise<{publicKey: CryptoKey, privateKey: CryptoKey}>}
 */
export async function generateEphemeralKeyPair() {
  try {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: ECC_CURVE,
      },
      false, // not extractable for security
      ['deriveKey', 'deriveBits']
    );
    return keyPair;
  } catch (error) {
    console.error('Failed to generate ephemeral key pair:', error);
    throw new Error('Ephemeral key generation failed');
  }
}

/**
 * Export public key to raw format for transmission
 * @param {CryptoKey} publicKey 
 * @returns {Promise<ArrayBuffer>}
 */
export async function exportPublicKey(publicKey) {
  try {
    return await window.crypto.subtle.exportKey(KEY_FORMAT, publicKey);
  } catch (error) {
    console.error('Failed to export public key:', error);
    throw new Error('Public key export failed');
  }
}

/**
 * Import public key from raw format
 * @param {ArrayBuffer} keyData 
 * @returns {Promise<CryptoKey>}
 */
export async function importPublicKey(keyData) {
  try {
    return await window.crypto.subtle.importKey(
      KEY_FORMAT,
      keyData,
      {
        name: 'ECDH',
        namedCurve: ECC_CURVE,
      },
      false, // not extractable
      [] // no key operations needed for imported public keys in ECDH
    );
  } catch (error) {
    console.error('Failed to import public key:', error);
    throw new Error('Public key import failed');
  }
}

/**
 * Perform ECDH key exchange to derive shared secret
 * @param {CryptoKey} privateKey - Our private key
 * @param {CryptoKey} publicKey - Other party's public key
 * @returns {Promise<ArrayBuffer>} - Shared secret bits
 */
export async function performECDH(privateKey, publicKey) {
  try {
    const sharedSecret = await window.crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: publicKey,
      },
      privateKey,
      384 // P-384 produces 384 bits
    );
    return sharedSecret;
  } catch (error) {
    console.error('ECDH key exchange failed:', error);
    throw new Error('Key exchange failed');
  }
}

/**
 * Derive AES key from shared secret using HKDF
 * @param {ArrayBuffer} sharedSecret 
 * @param {string} salt - Optional salt for key derivation
 * @returns {Promise<CryptoKey>} - Derived AES-256-GCM key
 */
export async function deriveSessionKey(sharedSecret, salt = 'SecureMessagingApp2024') {
  try {
    // First import the shared secret as an HKDF key
    const baseKey = await window.crypto.subtle.importKey(
      'raw',
      sharedSecret,
      { name: 'HKDF' },
      false,
      ['deriveKey']
    );

    // Derive AES-GCM key from the shared secret
    const sessionKey = await window.crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new TextEncoder().encode(salt),
        info: new TextEncoder().encode('session-key'),
      },
      baseKey,
      {
        name: 'AES-GCM',
        length: 256,
      },
      false, // not extractable for security
      ['encrypt', 'decrypt']
    );

    return sessionKey;
  } catch (error) {
    console.error('Session key derivation failed:', error);
    throw new Error('Session key derivation failed');
  }
}

/**
 * Convert ArrayBuffer to base64 string for storage/transmission
 * @param {ArrayBuffer} buffer 
 * @returns {string}
 */
export function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  bytes.forEach(byte => binary += String.fromCharCode(byte));
  return btoa(binary);
}

/**
 * Convert base64 string back to ArrayBuffer
 * @param {string} base64 
 * @returns {ArrayBuffer}
 */
export function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}