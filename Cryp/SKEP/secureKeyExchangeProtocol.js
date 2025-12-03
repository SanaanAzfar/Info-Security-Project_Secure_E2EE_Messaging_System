/**
 * Main Secure Key Exchange Protocol Orchestrator
 * Combines all modules to implement the complete custom key exchange protocol
 * Uses ECDH, ECDSA signatures, HKDF, and HMAC confirmation as required
 */

class SecureKeyExchangeProtocol {
  constructor(userId) {
    this.userId = userId;
    this.identityKeys = null;
    this.peers = new Map();  // peerId -> {ecdhPublicKey, ecdsaPublicKey, verified}
    this.sessions = new Map();  // sessionId -> session data
    this.pendingChallenges = new Map(); // challengeId -> {expectedResponse, peerId, timestamp}
    this.sessionCallbacks = new Map(); // sessionId -> {onReady, onError, onConfirmation}

    // Initialize modules
    this.protocolInit = new window.ProtocolInitialization ? new window.ProtocolInitialization() :
                       (typeof ProtocolInitialization !== 'undefined' ? new ProtocolInitialization() : null);
    this.keyExchange = new window.KeyExchangeProtocol ? new window.KeyExchangeProtocol() :
                      (typeof KeyExchangeProtocol !== 'undefined' ? new KeyExchangeProtocol() : null);
    this.keyDerivation = new window.KeyDerivation ? new window.KeyDerivation() :
                        (typeof KeyDerivation !== 'undefined' ? new KeyDerivation() : null);
    this.keyConfirmation = new window.KeyConfirmation ? new window.KeyConfirmation() :
                          (typeof KeyConfirmation !== 'undefined' ? new KeyConfirmation() : null);

    if (!this.protocolInit || !this.keyExchange || !this.keyDerivation || !this.keyConfirmation) {
      throw new Error('Missing required modules for SecureKeyExchangeProtocol');
    }
  }

  /**
   * Initializes the protocol by generating identity keys
   * @returns {Promise<void>}
   */
  async initialize() {
    try {
      this.identityKeys = await this.protocolInit.generateIdentityKeys(this.userId);
      console.log("✅ Secure Key Exchange Protocol initialized for:", this.userId);
    } catch (error) {
      throw new Error(`Protocol initialization failed: ${error.message}`);
    }
  }

  /**
   * Starts a new key exchange session with a peer
   * @param {string} peerId - The peer's ID
   * @returns {Promise<string>} The session ID
   */
  async startKeyExchange(peerId) {
    try {
      if (!this.identityKeys) {
        throw new Error("Protocol not initialized - call initialize() first");
      }

      // Generate a unique session ID
      const sessionId = this.generateSessionId();

      // Create and return the hello message
      const helloMessage = await this.keyExchange.createHelloMessage(
        this.userId, 
        peerId, 
        this.identityKeys.ecdhKeyPair, 
        this.identityKeys.ecdsaKeyPair
      );

      // Store initial session state
      this.sessions.set(sessionId, {
        id: sessionId,
        peerId: peerId,
        status: "initiated",
        createdAt: Date.now(),
        lastActivity: Date.now()
      });

      console.log(`Started key exchange with ${peerId}, session: ${sessionId}`);

      return {
        sessionId: sessionId,
        message: helloMessage
      };
    } catch (error) {
      throw new Error(`Key exchange start failed: ${error.message}`);
    }
  }

  /**
   * Processes a received hello message
   * @param {Object} message - The received hello message
   * @returns {Promise<Object>} Response message and session info
   */
  async processHelloMessage(message) {
    try {
      // Validate the received message
      if (!this.keyExchange.validateHelloMessage(message)) {
        throw new Error("Invalid hello message");
      }

      // Store peer's public keys
      this.peers.set(message.userId, {
        ecdhPublicKey: message.ecdhPublicKey,
        ecdsaPublicKey: message.ecdsaPublicKey,
        verified: false,  // Requires out-of-band verification
        addedAt: Date.now()
      });

      // Generate ephemeral key exchange in response
      const result = await this.keyExchange.createEphemeralKeyExchange(
        message.sessionId || this.generateSessionId(),
        message.userId,
        this.identityKeys
      );

      // Store the session
      this.sessions.set(result.session.id, result.session);

      return {
        sessionId: result.session.id,
        message: result.message,
        peerId: message.userId
      };
    } catch (error) {
      throw new Error(`Hello message processing failed: ${error.message}`);
    }
  }

  /**
   * Processes a received ephemeral key exchange message
   * @param {Object} message - The received ephemeral key exchange message
   * @param {string} sessionId - The session ID
   * @returns {Promise<Object>} Session keys and confirmation message
   */
  async processEphemeralMessage(message, sessionId) {
    try {
      // Validate the received message
      if (!await this.keyExchange.validateEphemeralMessage(message)) {
        throw new Error("Invalid ephemeral message");
      }

      const session = this.sessions.get(sessionId);
      if (!session) {
        throw new Error("Session not found");
      }

      // Get peer's stored public keys
      const peer = this.peers.get(session.peerId);
      if (!peer) {
        throw new Error("Peer not found");
      }

      // Verify signature and derive shared secret
      const sharedSecret = await this.keyExchange.verifyAndDeriveSharedSecret(
        session,
        message,
        peer.ecdsaPublicKey
      );

      // Generate random salt for HKDF
      const salt = await this.keyDerivation.generateSalt();

      // Derive session keys
      const sessionKeys = await this.keyDerivation.deriveSessionKeys(
        sharedSecret,
        salt,
        `session-${sessionId}-${this.userId}-${session.peerId}`
      );

      // Store session keys
      session.keys = sessionKeys;
      session.status = "keys_derived";

      // Initiate key confirmation
      const confirmation = await this.keyConfirmation.initiateKeyConfirmation(sessionKeys);
      
      // Store the expected response for later verification
      this.pendingChallenges.set(confirmation.challengeId, {
        expectedResponse: confirmation.expectedResponse,
        peerId: session.peerId,
        timestamp: Date.now(),
        sessionId: sessionId
      });

      // Create and return key confirmation challenge
      const confirmationMessage = this.keyConfirmation.createKeyConfirmationMessage(
        confirmation.challenge,
        confirmation.challengeId
      );

      return {
        sessionId: sessionId,
        message: confirmationMessage,
        keys: sessionKeys
      };
    } catch (error) {
      throw new Error(`Ephemeral message processing failed: ${error.message}`);
    }
  }

  /**
   * Processes a received key confirmation challenge
   * @param {Object} message - The received key confirmation challenge
   * @param {string} sessionId - The session ID
   * @returns {Promise<Object>} Response to the challenge
   */
  async processKeyConfirmationChallenge(message, sessionId) {
    try {
      // Validate the received message
      if (!this.keyConfirmation.validateKeyConfirmationMessage(message)) {
        throw new Error("Invalid key confirmation message");
      }

      const session = this.sessions.get(sessionId);
      if (!session || !session.keys) {
        throw new Error("Session or session keys not found");
      }

      // Respond to the challenge
      const response = await this.keyConfirmation.respondToKeyConfirmation(
        message.challenge,
        session.keys
      );

      // Create and return response message
      const responseMessage = this.keyConfirmation.createKeyConfirmationResponse(
        response,
        message.challengeId
      );

      return {
        sessionId: sessionId,
        message: responseMessage
      };
    } catch (error) {
      throw new Error(`Key confirmation challenge processing failed: ${error.message}`);
    }
  }

  /**
   * Processes a received key confirmation response
   * @param {Object} message - The received key confirmation response
   * @returns {Promise<boolean>} Whether the confirmation was successful
   */
  async processKeyConfirmationResponse(message) {
    try {
      // Validate the received message
      if (!this.keyConfirmation.validateKeyConfirmationMessage(message)) {
        throw new Error("Invalid key confirmation response");
      }

      // Get the stored expected response
      const challengeData = this.pendingChallenges.get(message.challengeId);
      if (!challengeData) {
        throw new Error("Challenge not found or expired");
      }

      // Verify the response matches expected
      const isConfirmed = this.keyConfirmation.verifyKeyConfirmationResponse(
        null,  // We don't need the original challenge here since we have expected response
        message.response,
        challengeData.expectedResponse
      );

      if (isConfirmed) {
        // Update session status
        const session = this.sessions.get(challengeData.sessionId);
        if (session) {
          session.status = "confirmed";
          session.confirmedAt = Date.now();
        }

        // Clean up the challenge
        this.pendingChallenges.delete(message.challengeId);

        console.log(`✅ Key confirmation successful for session: ${challengeData.sessionId}`);

        // Create and return session ready message
        const readyMessage = this.keyConfirmation.createSessionReadyMessage(challengeData.sessionId);

        return {
          success: true,
          sessionId: challengeData.sessionId,
          message: readyMessage
        };
      } else {
        throw new Error("Key confirmation failed - keys don't match (possible MITM attack)");
      }
    } catch (error) {
      throw new Error(`Key confirmation response processing failed: ${error.message}`);
    }
  }

  /**
   * Sets a callback for when a session is ready
   * @param {string} sessionId - The session ID
   * @param {Function} callback - The callback function
   */
  setSessionReadyCallback(sessionId, callback) {
    let callbacks = this.sessionCallbacks.get(sessionId);
    if (!callbacks) {
      callbacks = {};
    }
    callbacks.onReady = callback;
    this.sessionCallbacks.set(sessionId, callbacks);
  }

  /**
   * Gets the session keys for an active session
   * @param {string} sessionId - The session ID
   * @returns {Object} The session keys
   */
  getSessionKeys(sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session || !session.keys) {
      throw new Error(`Session ${sessionId} not found or not confirmed`);
    }

    if (session.status !== "confirmed") {
      throw new Error(`Session ${sessionId} is not confirmed yet`);
    }

    return session.keys;
  }

  /**
   * Gets the next IV for encrypting a message in the session
   * @param {string} sessionId - The session ID
   * @returns {Promise<Uint8Array>} The next IV
   */
  async getNextIV(sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session || !session.keys) {
      throw new Error(`Session ${sessionId} not found or has no keys`);
    }

    return await this.keyDerivation.getNextIV(session.keys);
  }

  /**
   * Generates a unique session ID
   * @returns {string} A unique session identifier
   */
  generateSessionId() {
    return `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Cleans up old challenges and sessions to prevent memory leaks
   */
  cleanup() {
    const now = Date.now();
    const timeout = 5 * 60 * 1000; // 5 minutes

    // Clean up old pending challenges
    for (const [id, challenge] of this.pendingChallenges) {
      if (now - challenge.timestamp > timeout) {
        this.pendingChallenges.delete(id);
      }
    }

    // Clean up old sessions (but keep confirmed ones)
    for (const [id, session] of this.sessions) {
      if (session.status !== "confirmed" && now - session.lastActivity > timeout) {
        this.sessions.delete(id);
      }
    }
  }

  /**
   * Gets the fingerprint for out-of-band verification
   * @param {CryptoKey} ecdhPublicKey - The ECDH public key
   * @param {CryptoKey} ecdsaPublicKey - The ECDSA public key
   * @returns {Promise<Object>} The fingerprint information
   */
  async getVerificationFingerprint(ecdhPublicKey, ecdsaPublicKey) {
    return await this.protocolInit.generateKeyFingerprint(ecdhPublicKey, ecdsaPublicKey);
  }
}

// Export the SecureKeyExchangeProtocol class
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { SecureKeyExchangeProtocol };
} else {
  window.SecureKeyExchangeProtocol = SecureKeyExchangeProtocol;
}