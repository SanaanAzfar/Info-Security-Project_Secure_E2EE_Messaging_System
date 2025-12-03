/**
 * Integrated Key Exchange System for Frontend
 * Combines the Secure Key Exchange Protocol (SKEP) with messaging functionality
 */

import { secureKeyExchange } from './secureKeyExchangeIntegration.js';

// Session manager to store active sessions
class SessionManager {
  constructor() {
    this.sessions = new Map(); // Map<userId, sessionData>
  }

  /**
   * Store a session for a user
   * @param {string} userId - Target user ID
   * @param {Object} sessionData - Session keys and metadata
   */
  storeSession(userId, sessionData) {
    this.sessions.set(userId, sessionData);
  }

  /**
   * Get a session for a user
   * @param {string} userId - Target user ID
   * @returns {Object|null} Session data or null if not found
   */
  getSession(userId) {
    return this.sessions.get(userId) || null;
  }

  /**
   * Check if a session exists for a user
   * @param {string} userId - Target user ID
   * @returns {boolean} Whether session exists
   */
  hasSession(userId) {
    return this.sessions.has(userId);
  }

  /**
   * Remove a session for a user
   * @param {string} userId - Target user ID
   */
  removeSession(userId) {
    this.sessions.delete(userId);
  }

  /**
   * Clear all sessions (for logout)
   */
  clearAllSessions() {
    this.sessions.clear();
  }

  /**
   * Get all active sessions
   * @returns {Array} Array of session entries
   */
  getAllSessions() {
    return Array.from(this.sessions.entries());
  }
}

// Create a global session manager instance
export const sessionManager = new SessionManager();

/**
 * Initialize a key exchange with another user
 * @param {string} currentUserId - Current user ID
 * @param {string} targetUserId - Target user ID
 * @param {Object} signingPrivateKey - Current user's signing private key
 * @returns {Promise<Object>} Key exchange message and ephemeral private key
 */
export async function initiateKeyExchange(currentUserId, targetUserId, signingPrivateKey) {
  // Create a new secure key exchange instance
  const keyExchange = secureKeyExchange(currentUserId);
  await keyExchange.initialize();

  // Generate the hello message to start key exchange
  const helloMessage = await keyExchange.createHelloMessage(targetUserId);

  return {
    keyExchangeMessage: helloMessage,
    keyExchangeInstance: keyExchange
  };
}

/**
 * Respond to a key exchange initiation from another user
 * @param {Object} message - Key exchange message from peer
 * @param {Object} signingPrivateKey - Current user's signing private key  
 * @param {Object} senderSigningKey - Sender's public signing key
 * @returns {Promise<Object>} Response message and session key
 */
export async function respondToKeyExchange(message, signingPrivateKey, senderSigningKey) {
  // Create a new secure key exchange instance
  const keyExchange = secureKeyExchange(message.receiverId);
  await keyExchange.initialize();

  // Process the received hello message
  // First, store the peer's public keys
  keyExchange.peers.set(message.senderId, {
    ecdhPublicKey: message.ecdhPublicKey,
    ecdsaPublicKey: message.ecdsaPublicKey,
    verified: false,
    addedAt: Date.now()
  });

  // Create ephemeral key exchange response
  const ephemeralMessage = await keyExchange.createEphemeralKeyExchange(
    message.sessionId || `session_${Date.now()}`,
    message.senderId
  );

  // In a complete implementation, we would:
  // 1. Verify the sender's signature on the original message
  // 2. Send the ephemeral key exchange back
  // 3. Process the final handshake

  // For now, return the ephemeral message as response
  return {
    responseMessage: ephemeralMessage,
    sessionKey: null // Will be available after complete handshake
  };
}

/**
 * Complete a key exchange after receiving peer's response
 * @param {Object} message - Peer's response message
 * @param {Object} localEphemeralPrivateKey - Local ephemeral private key
 * @param {Object} peerSigningKey - Peer's public signing key
 * @returns {Promise<Object>} Completed session information
 */
export async function completeKeyExchange(message, localEphemeralPrivateKey, peerSigningKey) {
  // This function would complete the key exchange process
  // In a complete implementation:
  // 1. Verify peer's signature on their ephemeral key
  // 2. Perform ECDH to derive shared secret
  // 3. Derive session keys using HKDF
  // 4. Perform key confirmation
  // 5. Return the session key for encryption/decryption

  // Return a placeholder for now - will be implemented with SKEP
  return {
    sessionKey: null // To be implemented with complete SKEP
  };
}

/**
 * Enhanced key exchange using the complete SKEP protocol
 */
export class EnhancedKeyExchange {
  constructor(userId) {
    this.userId = userId;
    this.skep = null;
    this.isInitialized = false;
  }

  async initialize() {
    this.skep = secureKeyExchange(this.userId);
    await this.skep.initialize();
    this.isInitialized = true;
  }

  /**
   * Start a complete key exchange using SKEP
   * @param {string} peerId - Peer user ID
   * @returns {Promise<Object>} Initial key exchange message
   */
  async startKeyExchange(peerId) {
    if (!this.isInitialized) {
      await this.initialize();
    }

    return await this.skep.createHelloMessage(peerId);
  }

  /**
   * Process a key exchange hello message
   * @param {Object} message - Hello message from peer
   * @returns {Promise<Object>} Response message
   */
  async processHelloMessage(message) {
    if (!this.isInitialized) {
      await this.initialize();
    }

    // Store peer's public keys
    this.skep.peers.set(message.userId, {
      ecdhPublicKey: message.ecdhPublicKey,
      ecdsaPublicKey: message.ecdsaPublicKey,
      verified: false
    });

    // Generate ephemeral key exchange response
    const sessionId = message.sessionId || `session_${Date.now()}_${this.userId}_${message.userId}`;
    return await this.skep.createEphemeralKeyExchange(sessionId, message.userId);
  }

  /**
   * Process a key exchange ephemeral message
   * @param {Object} message - Ephemeral message from peer
   * @returns {Promise<Object>} Confirmation message and session keys
   */
  async processEphemeralMessage(message, sessionId) {
    if (!this.isInitialized) {
      await this.initialize();
    }

    return await this.skep.processEphemeralMessage(message, sessionId);
  }

  /**
   * Process key confirmation response
   * @param {Object} message - Confirmation response
   * @returns {Promise<Object>} Confirmation result
   */
  async processKeyConfirmationResponse(message) {
    if (!this.isInitialized) {
      await this.initialize();
    }

    return await this.skep.processKeyConfirmationResponse(message);
  }

  /**
   * Get session keys for an established session
   * @param {string} sessionId - Session ID
   * @returns {Object} Session keys
   */
  getSessionKeys(sessionId) {
    if (!this.isInitialized) {
      throw new Error('Key exchange not initialized');
    }

    return this.skep.getSessionKeys(sessionId);
  }
}