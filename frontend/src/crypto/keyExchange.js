/**
 * Key exchange utilities for secure session establishment
 * Implements ECDH key exchange with digital signatures for MITM protection
 * Handles ephemeral key generation and session key derivation
 */

import { 
  generateEphemeralKeyPair, 
  exportPublicKey, 
  importPublicKey, 
  performECDH, 
  deriveSessionKey,
  arrayBufferToBase64,
  base64ToArrayBuffer
} from './ecc.js';

/**
 * Generate ECDSA key pair for message signing
 * @returns {Promise<{publicKey: CryptoKey, privateKey: CryptoKey}>}
 */
export async function generateSigningKeyPair() {
  try {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-384',
      },
      true, // extractable for export
      ['sign', 'verify']
    );
    return keyPair;
  } catch (error) {
    console.error('Failed to generate signing key pair:', error);
    throw new Error('Signing key generation failed');
  }
}

/**
 * Sign a message or key exchange data using ECDSA
 * @param {ArrayBuffer|string} data - Data to sign
 * @param {CryptoKey} privateKey - Private signing key
 * @returns {Promise<ArrayBuffer>} - Digital signature
 */
export async function signData(data, privateKey) {
  try {
    const encoder = new TextEncoder();
    const dataBuffer = typeof data === 'string' ? encoder.encode(data) : data;
    
    const signature = await window.crypto.subtle.sign(
      {
        name: 'ECDSA',
        hash: 'SHA-384',
      },
      privateKey,
      dataBuffer
    );
    
    return signature;
  } catch (error) {
    console.error('Data signing failed:', error);
    throw new Error('Signing failed');
  }
}

/**
 * Verify a digital signature using ECDSA
 * @param {ArrayBuffer} signature - Digital signature to verify
 * @param {ArrayBuffer|string} data - Original data that was signed
 * @param {CryptoKey} publicKey - Public key for verification
 * @returns {Promise<boolean>} - True if signature is valid
 */
export async function verifySignature(signature, data, publicKey) {
  try {
    const encoder = new TextEncoder();
    const dataBuffer = typeof data === 'string' ? encoder.encode(data) : data;
    
    const isValid = await window.crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: 'SHA-384',
      },
      publicKey,
      signature,
      dataBuffer
    );
    
    return isValid;
  } catch (error) {
    console.error('Signature verification failed:', error);
    return false;
  }
}

/**
 * Initiate key exchange (sender side)
 * @param {string} senderId - Sender user ID
 * @param {string} receiverId - Receiver user ID
 * @param {CryptoKey} senderSigningKey - Sender's private signing key
 * @returns {Promise<{keyExchangeMessage: Object, ephemeralPrivateKey: CryptoKey}>}
 */
export async function initiateKeyExchange(senderId, receiverId, senderSigningKey) {
  try {
    // Generate ephemeral key pair for this session
    const ephemeralKeyPair = await generateEphemeralKeyPair();
    const ephemeralPublicKeyData = await exportPublicKey(ephemeralKeyPair.publicKey);
    
    // Create key exchange message
    const timestamp = Date.now();
    const nonce = window.crypto.getRandomValues(new Uint8Array(16));
    
    // Prepare data for signing (public key + timestamp + nonce)
    const dataToSign = new Uint8Array(
      ephemeralPublicKeyData.byteLength + 8 + nonce.length
    );
    dataToSign.set(new Uint8Array(ephemeralPublicKeyData), 0);
    dataToSign.set(new Uint8Array(new BigUint64Array([BigInt(timestamp)]).buffer), ephemeralPublicKeyData.byteLength);
    dataToSign.set(nonce, ephemeralPublicKeyData.byteLength + 8);
    
    // Sign the key exchange data
    const signature = await signData(dataToSign, senderSigningKey);
    
    const keyExchangeMessage = {
      type: 'key_exchange_initiate',
      senderId,
      receiverId,
      ephemeralPublicKey: arrayBufferToBase64(ephemeralPublicKeyData),
      timestamp,
      nonce: arrayBufferToBase64(nonce.buffer),
      signature: arrayBufferToBase64(signature)
    };
    
    return {
      keyExchangeMessage,
      ephemeralPrivateKey: ephemeralKeyPair.privateKey
    };
  } catch (error) {
    console.error('Key exchange initiation failed:', error);
    throw new Error('Key exchange initiation failed');
  }
}

/**
 * Respond to key exchange (receiver side)
 * @param {Object} initiateMessage - Initial key exchange message
 * @param {CryptoKey} receiverSigningKey - Receiver's private signing key
 * @param {CryptoKey} senderVerifyKey - Sender's public verification key
 * @returns {Promise<{responseMessage: Object, sessionKey: CryptoKey}>}
 */
export async function respondToKeyExchange(initiateMessage, receiverSigningKey, senderVerifyKey) {
  try {
    // Verify the initiation message signature first
    const senderEphemeralPublicKeyData = base64ToArrayBuffer(initiateMessage.ephemeralPublicKey);
    const timestamp = initiateMessage.timestamp;
    const nonce = base64ToArrayBuffer(initiateMessage.nonce);
    const signature = base64ToArrayBuffer(initiateMessage.signature);
    
    // Reconstruct signed data
    const signedData = new Uint8Array(
      senderEphemeralPublicKeyData.byteLength + 8 + nonce.byteLength
    );
    signedData.set(new Uint8Array(senderEphemeralPublicKeyData), 0);
    signedData.set(new Uint8Array(new BigUint64Array([BigInt(timestamp)]).buffer), senderEphemeralPublicKeyData.byteLength);
    signedData.set(new Uint8Array(nonce), senderEphemeralPublicKeyData.byteLength + 8);
    
    // Verify sender's signature
    const isValidSignature = await verifySignature(signature, signedData, senderVerifyKey);
    if (!isValidSignature) {
      throw new Error('Invalid key exchange signature - possible MITM attack');
    }
    
    // Generate our ephemeral key pair
    const ourEphemeralKeyPair = await generateEphemeralKeyPair();
    const ourEphemeralPublicKeyData = await exportPublicKey(ourEphemeralKeyPair.publicKey);
    
    // Import sender's ephemeral public key
    const senderEphemeralPublicKey = await importPublicKey(senderEphemeralPublicKeyData);
    
    // Perform ECDH to get shared secret
    const sharedSecret = await performECDH(ourEphemeralKeyPair.privateKey, senderEphemeralPublicKey);
    
    // Derive session key
    const sessionKey = await deriveSessionKey(sharedSecret);
    
    // Create response message
    const responseTimestamp = Date.now();
    const responseNonce = window.crypto.getRandomValues(new Uint8Array(16));
    
    // Sign our response
    const responseSignData = new Uint8Array(
      ourEphemeralPublicKeyData.byteLength + 8 + responseNonce.length
    );
    responseSignData.set(new Uint8Array(ourEphemeralPublicKeyData), 0);
    responseSignData.set(new Uint8Array(new BigUint64Array([BigInt(responseTimestamp)]).buffer), ourEphemeralPublicKeyData.byteLength);
    responseSignData.set(responseNonce, ourEphemeralPublicKeyData.byteLength + 8);
    
    const responseSignature = await signData(responseSignData, receiverSigningKey);
    
    const responseMessage = {
      type: 'key_exchange_response',
      senderId: initiateMessage.receiverId,
      receiverId: initiateMessage.senderId,
      ephemeralPublicKey: arrayBufferToBase64(ourEphemeralPublicKeyData),
      timestamp: responseTimestamp,
      nonce: arrayBufferToBase64(responseNonce.buffer),
      signature: arrayBufferToBase64(responseSignature)
    };
    
    return { responseMessage, sessionKey };
  } catch (error) {
    console.error('Key exchange response failed:', error);
    throw new Error('Key exchange response failed');
  }
}

/**
 * Complete key exchange (original sender side)
 * @param {Object} responseMessage - Response message from receiver
 * @param {CryptoKey} ephemeralPrivateKey - Our ephemeral private key
 * @param {CryptoKey} receiverVerifyKey - Receiver's public verification key
 * @returns {Promise<{sessionKey: CryptoKey, confirmationMessage: Object}>}
 */
export async function completeKeyExchange(responseMessage, ephemeralPrivateKey, receiverVerifyKey) {
  try {
    // Verify response signature
    const receiverEphemeralPublicKeyData = base64ToArrayBuffer(responseMessage.ephemeralPublicKey);
    const timestamp = responseMessage.timestamp;
    const nonce = base64ToArrayBuffer(responseMessage.nonce);
    const signature = base64ToArrayBuffer(responseMessage.signature);
    
    // Reconstruct signed data
    const signedData = new Uint8Array(
      receiverEphemeralPublicKeyData.byteLength + 8 + nonce.byteLength
    );
    signedData.set(new Uint8Array(receiverEphemeralPublicKeyData), 0);
    signedData.set(new Uint8Array(new BigUint64Array([BigInt(timestamp)]).buffer), receiverEphemeralPublicKeyData.byteLength);
    signedData.set(new Uint8Array(nonce), receiverEphemeralPublicKeyData.byteLength + 8);
    
    // Verify receiver's signature
    const isValidSignature = await verifySignature(signature, signedData, receiverVerifyKey);
    if (!isValidSignature) {
      throw new Error('Invalid response signature - possible MITM attack');
    }
    
    // Import receiver's ephemeral public key
    const receiverEphemeralPublicKey = await importPublicKey(receiverEphemeralPublicKeyData);
    
    // Perform ECDH to get shared secret
    const sharedSecret = await performECDH(ephemeralPrivateKey, receiverEphemeralPublicKey);
    
    // Derive session key
    const sessionKey = await deriveSessionKey(sharedSecret);
    
    // Create confirmation message
    const confirmationMessage = {
      type: 'key_exchange_confirmation',
      senderId: responseMessage.receiverId,
      receiverId: responseMessage.senderId,
      timestamp: Date.now(),
      status: 'completed'
    };
    
    return { sessionKey, confirmationMessage };
  } catch (error) {
    console.error('Key exchange completion failed:', error);
    throw new Error('Key exchange completion failed');
  }
}

/**
 * In-memory session storage for active sessions
 */
class SessionManager {
  constructor() {
    this.sessions = new Map(); // Map<userId, {sessionKey, usedNonces, sequenceNumber}>
    this.sessionTimeouts = new Map(); // Map<userId, timeoutId>
  }
  
  /**
   * Store session key with metadata
   * @param {string} userId - Other party's user ID
   * @param {CryptoKey} sessionKey - Derived session key
   */
  storeSession(userId, sessionKey) {
    // Clear any existing session
    this.clearSession(userId);
    
    this.sessions.set(userId, {
      sessionKey,
      usedNonces: new Set(),
      sequenceNumber: 0,
      createdAt: Date.now()
    });
    
    // Auto-expire session after 24 hours
    const timeoutId = setTimeout(() => {
      this.clearSession(userId);
    }, 24 * 60 * 60 * 1000);
    
    this.sessionTimeouts.set(userId, timeoutId);
  }
  
  /**
   * Get session data for a user
   * @param {string} userId - User ID
   * @returns {Object|null} - Session data or null if not found
   */
  getSession(userId) {
    return this.sessions.get(userId) || null;
  }
  
  /**
   * Clear session for a user
   * @param {string} userId - User ID
   */
  clearSession(userId) {
    this.sessions.delete(userId);
    const timeoutId = this.sessionTimeouts.get(userId);
    if (timeoutId) {
      clearTimeout(timeoutId);
      this.sessionTimeouts.delete(userId);
    }
  }
  
  /**
   * Clear all sessions
   */
  clearAllSessions() {
    for (const timeoutId of this.sessionTimeouts.values()) {
      clearTimeout(timeoutId);
    }
    this.sessions.clear();
    this.sessionTimeouts.clear();
  }
}

// Export singleton session manager
export const sessionManager = new SessionManager();