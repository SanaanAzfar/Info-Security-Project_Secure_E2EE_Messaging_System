/**
 * Core encryption utilities for end-to-end encrypted messaging
 * Uses AES-256-GCM for message encryption with authentication
 * Implements replay attack protection with nonces and timestamps
 */

/**
 * Generate a cryptographically secure random nonce
 * @param {number} length - Length in bytes (default: 16)
 * @returns {Uint8Array}
 */
export function generateNonce(length = 16) {
  return window.crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Generate a random IV for AES-GCM encryption
 * @returns {Uint8Array} - 12-byte IV for GCM mode
 */
export function generateIV() {
  return window.crypto.getRandomValues(new Uint8Array(12));
}

/**
 * Generate a deterministic IV for AES-GCM encryption using IV seed and counter
 * This ensures IV uniqueness for the same session
 * @param {Uint8Array} ivSeed - The IV seed from key derivation
 * @param {number} counter - The message counter
 * @returns {Promise<Uint8Array>} - 12-byte IV for GCM mode
 */
export async function generateDeterministicIV(ivSeed, counter) {
  try {
    // Combine IV seed with message counter to create unique IV
    const combined = new Uint8Array([...ivSeed, ...new Uint8Array(new Uint32Array([counter]).buffer)]);

    // Hash the combination to get a 12-byte IV (as required by AES-GCM)
    const hashBuffer = await window.crypto.subtle.digest("SHA-256", combined);
    return new Uint8Array(hashBuffer.slice(0, 12));  // 12 bytes for AES-GCM
  } catch (error) {
    console.error('IV generation failed:', error);
    throw new Error('IV generation failed');
  }
}

/**
 * Encrypt a message using AES-256-GCM
 * @param {string} message - Plain text message to encrypt
 * @param {CryptoKey} key - AES-256-GCM encryption key
 * @param {Uint8Array} iv - Initialization vector (12 bytes for GCM)
 * @returns {Promise<{ciphertext: ArrayBuffer, authTag: ArrayBuffer}>}
 */
export async function encryptMessage(message, key, iv) {
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);

    const encrypted = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128, // 128-bit authentication tag
      },
      key,
      data
    );

    // GCM mode includes the auth tag in the result
    // Split ciphertext and auth tag (last 16 bytes)
    const ciphertext = encrypted.slice(0, -16);
    const authTag = encrypted.slice(-16);

    return { ciphertext, authTag };
  } catch (error) {
    console.error('Message encryption failed:', error);
    throw new Error('Encryption failed');
  }
}

/**
 * Decrypt a message using AES-256-GCM
 * @param {ArrayBuffer} ciphertext - Encrypted message
 * @param {ArrayBuffer} authTag - Authentication tag
 * @param {CryptoKey} key - AES-256-GCM decryption key
 * @param {Uint8Array} iv - Initialization vector
 * @returns {Promise<string>} - Decrypted plain text message
 */
export async function decryptMessage(ciphertext, authTag, key, iv) {
  try {
    // Combine ciphertext and auth tag for GCM decryption
    const combined = new Uint8Array(ciphertext.byteLength + authTag.byteLength);
    combined.set(new Uint8Array(ciphertext), 0);
    combined.set(new Uint8Array(authTag), ciphertext.byteLength);

    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128,
      },
      key,
      combined
    );

    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  } catch (error) {
    console.error('Message decryption failed:', error);
    throw new Error('Decryption failed - message may be tampered');
  }
}

/**
 * Create a complete encrypted message object with metadata
 * @param {string} message - Plain text message
 * @param {string} senderId - Sender user ID
 * @param {string} receiverId - Receiver user ID
 * @param {CryptoKey} sessionKey - Shared session key for encryption
 * @param {number} sequenceNumber - Message sequence number for replay protection
 * @param {Object} sessionMetadata - Additional session metadata (e.g., from SKEP)
 * @returns {Promise<Object>} - Complete encrypted message object
 */
export async function createEncryptedMessage(message, senderId, receiverId, sessionKey, sequenceNumber, sessionMetadata = null) {
  try {
    const timestamp = Date.now();
    const nonce = generateNonce();

    // Use deterministic IV if session metadata is available (from SKEP)
    let iv;
    if (sessionMetadata && sessionMetadata.ivSeed && typeof sessionMetadata.messageCount === 'number') {
      iv = await generateDeterministicIV(sessionMetadata.ivSeed, sessionMetadata.messageCount);
      // Increment message count for next message
      sessionMetadata.messageCount++;
    } else {
      iv = generateIV();
    }

    const { ciphertext, authTag } = await encryptMessage(message, sessionKey, iv);

    return {
      senderId,
      receiverId,
      ciphertext: arrayBufferToBase64(ciphertext),
      iv: arrayBufferToBase64(iv.buffer),
      authTag: arrayBufferToBase64(authTag),
      timestamp,
      nonce: arrayBufferToBase64(nonce.buffer),
      sequenceNumber,
      signature: null // Will be added by signing function
    };
  } catch (error) {
    console.error('Failed to create encrypted message:', error);
    throw new Error('Message creation failed');
  }
}

/**
 * Decrypt and verify a received message
 * @param {Object} encryptedMessage - Received encrypted message object
 * @param {CryptoKey} sessionKey - Shared session key for decryption
 * @param {number} expectedSequenceNumber - Expected sequence number
 * @param {Set} usedNonces - Set of previously used nonces for replay protection
 * @returns {Promise<{message: string, isValid: boolean, error?: string}>}
 */
export async function decryptReceivedMessage(encryptedMessage, sessionKey, expectedSequenceNumber, usedNonces) {
  try {
    // Verify timestamp (reject messages older than 5 minutes)
    const now = Date.now();
    const messageAge = now - encryptedMessage.timestamp;
    if (messageAge > 300000) { // 5 minutes in milliseconds
      return { message: null, isValid: false, error: 'Message too old' };
    }

    // Check for replay attack - nonce reuse
    const nonceStr = encryptedMessage.nonce;
    if (usedNonces.has(nonceStr)) {
      return { message: null, isValid: false, error: 'Nonce reused - possible replay attack' };
    }

    // Check sequence number
    if (encryptedMessage.sequenceNumber !== expectedSequenceNumber) {
      return { message: null, isValid: false, error: 'Invalid sequence number' };
    }

    // Convert base64 back to ArrayBuffer
    const ciphertext = base64ToArrayBuffer(encryptedMessage.ciphertext);
    const authTag = base64ToArrayBuffer(encryptedMessage.authTag);
    const iv = new Uint8Array(base64ToArrayBuffer(encryptedMessage.iv));

    // Decrypt the message
    const message = await decryptMessage(ciphertext, authTag, sessionKey, iv);

    // Mark nonce as used
    usedNonces.add(nonceStr);

    return { message, isValid: true };
  } catch (error) {
    console.error('Failed to decrypt received message:', error);
    return { message: null, isValid: false, error: error.message };
  }
}

/**
 * Utility functions for base64 encoding/decoding
 */
export function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  bytes.forEach(byte => binary += String.fromCharCode(byte));
  return btoa(binary);
}

export function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}