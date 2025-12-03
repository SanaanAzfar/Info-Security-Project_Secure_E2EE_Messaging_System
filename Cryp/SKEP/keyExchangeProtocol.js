/**
 * Key Exchange Protocol Module
 * Implements the core ECDH key exchange with signature verification
 */

class KeyExchangeProtocol {
  constructor() {
    // Configuration
    this.config = {
      rekeyInterval: 3 * 60 * 60 * 1000,  // 3 hours
      maxMessagesPerKey: 1000,
      inactivityTimeout: 30 * 60 * 1000,   // 30 minutes
      confirmationTimeout: 30 * 1000       // 30 seconds
    };
  }

  /**
   * Creates the initial hello message to exchange public keys
   * @param {string} userId - The current user's ID
   * @param {string} peerId - The peer's ID
   * @param {CryptoKeyPair} ecdhKeyPair - The ECDH key pair
   * @param {CryptoKeyPair} ecdsaKeyPair - The ECDSA key pair
   * @returns {Promise<Object>} The hello message
   */
  async createHelloMessage(userId, peerId, ecdhKeyPair, ecdsaKeyPair) {
    try {
      // Export public keys in SPKI format
      const ecdhPublic = await window.crypto.subtle.exportKey(
        "spki",
        ecdhKeyPair.publicKey
      );

      const ecdsaPublic = await window.crypto.subtle.exportKey(
        "spki",
        ecdsaKeyPair.publicKey
      );

      return {
        type: "KEY_EXCHANGE_HELLO",
        version: "1.0",
        userId: userId,
        peerId: peerId,
        ecdhPublicKey: Array.from(new Uint8Array(ecdhPublic)),
        ecdsaPublicKey: Array.from(new Uint8Array(ecdsaPublic)),
        timestamp: Date.now(),
        nonce: Array.from(window.crypto.getRandomValues(new Uint8Array(16)))
      };
    } catch (error) {
      throw new Error(`Hello message creation failed: ${error.message}`);
    }
  }

  /**
   * Creates an ephemeral key exchange message with signature
   * @param {string} sessionId - The session ID
   * @param {string} peerId - The peer's ID
   * @param {CryptoKeyPair} identityKeys - The user's identity keys
   * @returns {Promise<Object>} The ephemeral key exchange message
   */
  async createEphemeralKeyExchange(sessionId, peerId, identityKeys) {
    try {
      // Generate ephemeral ECDH keypair for this session only (forward secrecy)
      const ephemeralKeyPair = await window.crypto.subtle.generateKey(
        {
          name: "ECDH",
          namedCurve: "P-256"
        },
        true,
        ["deriveKey"]
      );

      // Export ephemeral public key in raw format (smaller size)
      const ephemeralPublic = await window.crypto.subtle.exportKey(
        "raw",
        ephemeralKeyPair.publicKey
      );

      // Sign ephemeral key with long-term identity key (ECDSA)
      const signature = await window.crypto.subtle.sign(
        {
          name: "ECDSA",
          hash: "SHA-256"
        },
        identityKeys.ecdsaKeyPair.privateKey,
        ephemeralPublic
      );

      // Store session state temporarily
      const session = {
        id: sessionId,
        peerId: peerId,
        localEphemeral: ephemeralKeyPair,
        sharedSecret: null,
        status: "ephemeral_created",
        createdAt: Date.now()
      };

      return {
        message: {
          type: "EPHEMERAL_KEY_EXCHANGE",
          sessionId: sessionId,
          ephemeralPublicKey: Array.from(new Uint8Array(ephemeralPublic)),
          signature: Array.from(new Uint8Array(signature)),
          timestamp: Date.now()
        },
        session: session
      };
    } catch (error) {
      throw new Error(`Ephemeral key exchange creation failed: ${error.message}`);
    }
  }

  /**
   * Verifies peer's signature and derives shared secret using ECDH
   * @param {Object} session - The session object
   * @param {Object} peerEphemeralData - Data from peer's ephemeral key exchange
   * @param {ArrayBuffer} peerEcdsaPublicKey - Peer's ECDSA public key
   * @returns {Promise<ArrayBuffer>} The shared secret
   */
  async verifyAndDeriveSharedSecret(session, peerEphemeralData, peerEcdsaPublicKey) {
    try {
      // 1. Import peer's long-term ECDSA public key
      const peerEcdsaKey = await window.crypto.subtle.importKey(
        "spki",
        new Uint8Array(peerEcdsaPublicKey),
        {
          name: "ECDSA",
          namedCurve: "P-256"
        },
        true,
        ["verify"]
      );

      // 2. Verify signature on ephemeral key to prevent MITM
      const ephemeralKeyBytes = new Uint8Array(peerEphemeralData.ephemeralPublicKey);
      const signatureBytes = new Uint8Array(peerEphemeralData.signature);

      const isValid = await window.crypto.subtle.verify(
        {
          name: "ECDSA",
          hash: "SHA-256"
        },
        peerEcdsaKey,
        signatureBytes,
        ephemeralKeyBytes
      );

      if (!isValid) {
        throw new Error("Invalid signature - possible MITM attack!");
      }

      // 3. Import peer's ephemeral public key
      const peerEphemeralKey = await window.crypto.subtle.importKey(
        "raw",
        ephemeralKeyBytes,
        {
          name: "ECDH",
          namedCurve: "P-256"
        },
        true,
        []
      );

      // 4. Perform ECDH to get shared secret
      const sharedSecret = await window.crypto.subtle.deriveBits(
        {
          name: "ECDH",
          public: peerEphemeralKey
        },
        session.localEphemeral.privateKey,
        256  // 256 bits for AES-256
      );

      session.sharedSecret = sharedSecret;
      session.status = "shared_secret_derived";

      return sharedSecret;
    } catch (error) {
      throw new Error(`Shared secret derivation failed: ${error.message}`);
    }
  }

  /**
   * Validates received hello message
   * @param {Object} message - The received hello message
   * @returns {boolean} True if valid, false otherwise
   */
  validateHelloMessage(message) {
    try {
      // Validate required fields
      if (!message || !message.type || !message.userId || !message.peerId) {
        return false;
      }

      if (message.type !== "KEY_EXCHANGE_HELLO") {
        return false;
      }

      if (!message.ecdhPublicKey || !message.ecdsaPublicKey) {
        return false;
      }

      if (!message.timestamp || Date.now() - message.timestamp > 300000) {  // 5 minutes
        return false;  // Message too old
      }

      return true;
    } catch (error) {
      console.error('Error validating hello message:', error);
      return false;
    }
  }

  /**
   * Validates received ephemeral key exchange message
   * @param {Object} message - The received ephemeral key exchange message
   * @returns {Promise<boolean>} True if valid, false otherwise
   */
  async validateEphemeralMessage(message) {
    try {
      // Validate required fields
      if (!message || !message.type || !message.sessionId) {
        return false;
      }

      if (message.type !== "EPHEMERAL_KEY_EXCHANGE") {
        return false;
      }

      if (!message.ephemeralPublicKey || !message.signature) {
        return false;
      }

      if (!message.timestamp || Date.now() - message.timestamp > 300000) {  // 5 minutes
        return false;  // Message too old
      }

      return true;
    } catch (error) {
      console.error('Error validating ephemeral message:', error);
      return false;
    }
  }
}

// Export the KeyExchangeProtocol class
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { KeyExchangeProtocol };
} else {
  window.KeyExchangeProtocol = KeyExchangeProtocol;
}