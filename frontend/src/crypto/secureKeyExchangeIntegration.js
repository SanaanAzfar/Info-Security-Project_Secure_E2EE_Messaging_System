/**
 * Secure Key Exchange Protocol Integration for Frontend
 * Integrates the SKEP module into the frontend
 */

/**
 * Simplified Secure Key Exchange for Frontend
 * Implements the core SKEP functionality adapted for frontend use
 */
export class SimplifiedSecureKeyExchange {
  constructor(userId) {
    this.userId = userId;
    this.identityKeys = null;
    this.peers = new Map();  // peerId -> {ecdhPublicKey, ecdsaPublicKey, verified}
    this.sessions = new Map();  // sessionId -> session data
    this.pendingChallenges = new Map(); // challengeId -> {expectedResponse, peerId, timestamp}
    
    // Use P-256 curve as required
    this.curve = "P-256";
  }

  /**
   * Initializes the protocol by generating identity keys
   * @returns {Promise<void>}
   */
  async initialize() {
    try {
      // Generate ECDH keypair for key exchange (uses P-256 as required)
      const ecdhKeyPair = await window.crypto.subtle.generateKey(
        {
          name: "ECDH",
          namedCurve: this.curve  // 256-bit security level as required
        },
        true,  // extractable (for export)
        ["deriveKey", "deriveBits"]  // key usage
      );

      // Generate ECDSA keypair for digital signatures (uses P-256 as required)
      const ecdsaKeyPair = await window.crypto.subtle.generateKey(
        {
          name: "ECDSA",
          namedCurve: this.curve  // Matching curve for consistency
        },
        true,  // extractable
        ["sign", "verify"]  // key usage
      );

      this.identityKeys = {
        userId: this.userId,
        ecdhKeyPair: ecdhKeyPair,
        ecdsaKeyPair: ecdsaKeyPair,
        generatedAt: Date.now()
      };
      
      console.log("✅ Secure Key Exchange Protocol initialized for:", this.userId);
    } catch (error) {
      throw new Error(`Protocol initialization failed: ${error.message}`);
    }
  }

  /**
   * Generates a key fingerprint for MITM protection
   * @param {CryptoKey} ecdhPublicKey - The ECDH public key
   * @param {CryptoKey} ecdsaPublicKey - The ECDSA public key
   * @returns {Promise<Object>} The fingerprint information
   */
  async generateKeyFingerprint(ecdhPublicKey, ecdsaPublicKey) {
    try {
      // Export both public keys to binary format
      const ecdhBytes = await window.crypto.subtle.exportKey("spki", ecdhPublicKey);
      const ecdsaBytes = await window.crypto.subtle.exportKey("spki", ecdsaPublicKey);

      // Concatenate and hash using SHA-256
      const combined = new Uint8Array([
        ...new Uint8Array(ecdhBytes),
        ...new Uint8Array(ecdsaBytes)
      ]);

      const hash = await window.crypto.subtle.digest("SHA-256", combined);
      const hashArray = Array.from(new Uint8Array(hash));

      // Format for human verification
      return {
        // Full hex for technical verification
        hex: hashArray.map(b => b.toString(16).padStart(2, '0')).join(':'),

        // Numeric code for phone verification (like Signal)
        numeric: this.formatNumericCode(hashArray),

        // Emoji code for visual verification
        emoji: this.formatEmojiCode(hashArray)
      };
    } catch (error) {
      throw new Error(`Fingerprint generation failed: ${error.message}`);
    }
  }

  /**
   * Formats the hash as a numeric code for human verification
   * @param {Array} hashArray - The SHA-256 hash array
   * @returns {string} Formatted numeric code
   */
  formatNumericCode(hashArray) {
    // Use first 60 bits (8 characters from 240-bit hash) and format as 6 groups of 3 digits
    const first15Bytes = hashArray.slice(0, 15);  // 120 bits
    let binary = '';
    
    for (const byte of first15Bytes) {
      binary += byte.toString(2).padStart(8, '0');
    }
    
    // Split into 6 groups of 10 bits each (60 bits total)
    const groups = [];
    for (let i = 0; i < 6; i++) {
      const start = i * 10;
      const end = start + 10;
      const bits = binary.slice(start, end);
      const num = parseInt(bits, 2);
      groups.push(num.toString().padStart(3, '0'));  // Pad to 3 digits
    }
    
    return groups.join('-');
  }

  /**
   * Formats the hash as an emoji code for visual verification
   * @param {Array} hashArray - The SHA-256 hash array
   * @returns {string} Emoji-based code
   */
  formatEmojiCode(hashArray) {
    // Use a predefined emoji mapping based on the hash
    const emojis = [
      '😀', '😂', '🤣', '😍', '🥰', '😘', '🤩', '😎', '🥳', '😭',
      '😡', '🤯', '🥶', '😱', '🤠', '🥴', '😈', '👻', '🤖', '👾',
      '👋', '👍', '👏', '👏', '🙌', '👐', '🤝', '👍', '👎', '👊',
      '✊', '🤛', '🤜', '🤞', '✌️', '🤟', '🤘', '👌', '👈', '👉',
      '👆', '👇', '☝️', '✋', '🤚', '🖐', '🖖', '👋', '🤙', '💪'
    ];
    
    // Use first 6 bytes to select 6 emojis
    const selectedEmojis = [];
    for (let i = 0; i < 6; i++) {
      const index = hashArray[i] % emojis.length;
      selectedEmojis.push(emojis[index]);
    }
    
    return selectedEmojis.join(' ');
  }

  /**
   * Creates the initial hello message to exchange public keys
   * @param {string} peerId - The peer's ID
   * @returns {Promise<Object>} The hello message
   */
  async createHelloMessage(peerId) {
    try {
      // Export public keys in SPKI format
      const ecdhPublic = await window.crypto.subtle.exportKey(
        "spki",
        this.identityKeys.ecdhKeyPair.publicKey
      );

      const ecdsaPublic = await window.crypto.subtle.exportKey(
        "spki",
        this.identityKeys.ecdsaKeyPair.publicKey
      );

      return {
        type: "KEY_EXCHANGE_HELLO",
        version: "1.0",
        userId: this.userId,
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
   * @returns {Promise<Object>} The ephemeral key exchange message
   */
  async createEphemeralKeyExchange(sessionId, peerId) {
    try {
      // Generate ephemeral ECDH keypair for this session only (forward secrecy)
      const ephemeralKeyPair = await window.crypto.subtle.generateKey(
        {
          name: "ECDH",
          namedCurve: this.curve
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
        this.identityKeys.ecdsaKeyPair.privateKey,
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

      // Update our session store
      this.sessions.set(sessionId, session);

      return {
        type: "EPHEMERAL_KEY_EXCHANGE",
        sessionId: sessionId,
        ephemeralPublicKey: Array.from(new Uint8Array(ephemeralPublic)),
        signature: Array.from(new Uint8Array(signature)),
        timestamp: Date.now()
      };
    } catch (error) {
      throw new Error(`Ephemeral key exchange creation failed: ${error.message}`);
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
      const session = this.sessions.get(sessionId);
      if (!session) {
        throw new Error("Session not found");
      }

      // Get peer's stored public keys
      const peer = this.peers.get(session.peerId);
      if (!peer) {
        throw new Error("Peer not found");
      }

      // Import peer's ECDSA public key
      const peerEcdsaKey = await window.crypto.subtle.importKey(
        "spki",
        new Uint8Array(peer.ecdsaPublicKey),
        {
          name: "ECDSA",
          namedCurve: this.curve
        },
        true,
        ["verify"]
      );

      // Verify signature on ephemeral key to prevent MITM
      const ephemeralKeyBytes = new Uint8Array(message.ephemeralPublicKey);
      const signatureBytes = new Uint8Array(message.signature);

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

      // Import peer's ephemeral public key
      const peerEphemeralKey = await window.crypto.subtle.importKey(
        "raw",
        ephemeralKeyBytes,
        {
          name: "ECDH",
          namedCurve: this.curve
        },
        true,
        []
      );

      session.peerEphemeral = peerEphemeralKey;

      // Perform ECDH to get shared secret
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

      // Generate random salt for HKDF
      const salt = window.crypto.getRandomValues(new Uint8Array(32)).buffer;

      // Derive session keys using HKDF (as required)
      const sessionKeys = await this.deriveSessionKeys(
        sharedSecret,
        salt,
        `session-${sessionId}-${this.userId}-${session.peerId}`
      );

      // Store session keys
      session.keys = sessionKeys;
      session.status = "keys_derived";

      // Initiate key confirmation
      const confirmation = await this.initiateKeyConfirmation(sessionKeys);
      
      // Store the expected response for later verification
      this.pendingChallenges.set(confirmation.challengeId, {
        expectedResponse: confirmation.expectedResponse,
        peerId: session.peerId,
        timestamp: Date.now(),
        sessionId: sessionId
      });

      // Create and return key confirmation challenge
      const confirmationMessage = this.createKeyConfirmationMessage(
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
   * Derives session keys using HKDF from the shared secret
   * Creates multiple keys for different purposes: encryption, HMAC confirmation, IV generation
   * @param {ArrayBuffer} sharedSecret - The ECDH shared secret
   * @param {ArrayBuffer} salt - Salt for HKDF (should be random)
   * @param {string} contextInfo - Context information for key derivation
   * @returns {Promise<Object>} Derived session keys
   */
  async deriveSessionKeys(sharedSecret, salt, contextInfo) {
    try {
      // Import shared secret as HKDF base key
      const baseKey = await window.crypto.subtle.importKey(
        "raw",
        sharedSecret,
        "HKDF",
        false,  // NOT extractable
        ["deriveKey", "deriveBits"]
      );

      // Derive encryption key (AES-GCM 256-bit)
      const encryptionKey = await window.crypto.subtle.deriveKey(
        {
          name: "HKDF",
          salt: salt,
          info: new TextEncoder().encode(`${contextInfo}-encryption`),
          hash: "SHA-256"
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        true,  // extractable for export if needed
        ["encrypt", "decrypt"]
      );

      // Derive HMAC key for key confirmation
      const hmacKey = await window.crypto.subtle.deriveKey(
        {
          name: "HKDF",
          salt: salt,
          info: new TextEncoder().encode(`${contextInfo}-confirmation`),
          hash: "SHA-256"
        },
        baseKey,
        { name: "HMAC", hash: "SHA-256" },
        true,
        ["sign", "verify"]
      );

      // Derive IV seed for deterministic IV generation
      const ivSeed = await window.crypto.subtle.deriveBits(
        {
          name: "HKDF",
          salt: salt,
          info: new TextEncoder().encode(`${contextInfo}-iv-seed`),
          hash: "SHA-256"
        },
        baseKey,
        128  // 128 bits for IV seed
      );

      // Derive authentication key for message authentication
      const authKey = await window.crypto.subtle.deriveKey(
        {
          name: "HKDF",
          salt: salt,
          info: new TextEncoder().encode(`${contextInfo}-authentication`),
          hash: "SHA-256"
        },
        baseKey,
        { name: "HMAC", hash: "SHA-256" },
        true,
        ["sign", "verify"]
      );

      return {
        encryptionKey: encryptionKey,
        hmacKey: hmacKey,
        authKey: authKey,
        ivSeed: new Uint8Array(ivSeed),
        derivedAt: Date.now(),
        salt: salt,
        messageCount: 0
      };
    } catch (error) {
      throw new Error(`Session key derivation failed: ${error.message}`);
    }
  }

  /**
   * Initiates the key confirmation process by generating a random challenge
   * @param {Object} sessionKeys - The session keys object containing the HMAC key
   * @returns {Promise<Object>} Object containing the challenge and expected response
   */
  async initiateKeyConfirmation(sessionKeys) {
    try {
      if (!sessionKeys?.hmacKey) {
        throw new Error("Session HMAC key not available");
      }

      // Generate random challenge (32 bytes)
      const challenge = window.crypto.getRandomValues(new Uint8Array(32));

      // Compute expected response locally using the session HMAC key
      const expectedResponse = await window.crypto.subtle.sign(
        "HMAC",
        sessionKeys.hmacKey,
        challenge
      );

      return {
        challenge: Array.from(challenge),
        expectedResponse: Array.from(new Uint8Array(expectedResponse)),
        challengeId: this.generateChallengeId() // For tracking multiple challenges
      };
    } catch (error) {
      throw new Error(`Key confirmation initiation failed: ${error.message}`);
    }
  }

  /**
   * Creates a key confirmation message to send
   * @param {Array<number>} challenge - The challenge to send
   * @param {string} challengeId - The unique ID for this challenge
   * @returns {Object} The key confirmation message
   */
  createKeyConfirmationMessage(challenge, challengeId) {
    return {
      type: "KEY_CONFIRMATION_CHALLENGE",
      challenge: challenge,
      challengeId: challengeId,
      timestamp: Date.now()
    };
  }

  /**
   * Responds to a key confirmation challenge
   * @param {Array<number>} challenge - The received challenge as array of numbers
   * @param {Object} sessionKeys - The session keys object containing the HMAC key
   * @returns {Promise<Array<number>>} The HMAC response to the challenge
   */
  async respondToKeyConfirmation(challenge, sessionKeys) {
    try {
      if (!sessionKeys?.hmacKey) {
        throw new Error("Session HMAC key not available");
      }

      // Convert challenge back to Uint8Array
      const challengeBytes = new Uint8Array(challenge);

      // Compute HMAC response using the session HMAC key
      const response = await window.crypto.subtle.sign(
        "HMAC",
        sessionKeys.hmacKey,
        challengeBytes
      );

      return Array.from(new Uint8Array(response));
    } catch (error) {
      throw new Error(`Key confirmation response failed: ${error.message}`);
    }
  }

  /**
   * Creates a key confirmation response message
   * @param {Array<number>} response - The HMAC response to the challenge
   * @param {string} challengeId - The ID of the challenge being responded to
   * @returns {Object} The key confirmation response message
   */
  createKeyConfirmationResponse(response, challengeId) {
    return {
      type: "KEY_CONFIRMATION_RESPONSE",
      response: response,
      challengeId: challengeId,
      timestamp: Date.now()
    };
  }

  /**
   * Processes a received key confirmation response
   * @param {Object} message - The received key confirmation response
   * @returns {Promise<boolean>} Whether the confirmation was successful
   */
  async processKeyConfirmationResponse(message) {
    try {
      // Get the stored expected response
      const challengeData = this.pendingChallenges.get(message.challengeId);
      if (!challengeData) {
        throw new Error("Challenge not found or expired");
      }

      // Verify the response matches expected
      const isConfirmed = this.verifyKeyConfirmationResponse(
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

        return {
          success: true,
          sessionId: challengeData.sessionId
        };
      } else {
        throw new Error("Key confirmation failed - keys don't match (possible MITM attack)");
      }
    } catch (error) {
      throw new Error(`Key confirmation response processing failed: ${error.message}`);
    }
  }

  /**
   * Verifies the response to our challenge
   * @param {Array<number>} challenge - The original challenge
   * @param {Array<number>} response - The received response
   * @param {Array<number>} expectedResponse - The locally computed expected response
   * @returns {boolean} Whether the response matches the expected response
   */
  verifyKeyConfirmationResponse(challenge, response, expectedResponse) {
    try {
      // Convert arrays back to Uint8Arrays for comparison
      const responseBytes = new Uint8Array(response);
      const expectedResponseBytes = new Uint8Array(expectedResponse);

      // Check if lengths match
      if (responseBytes.length !== expectedResponseBytes.length) {
        return false;
      }

      // Compare each byte
      for (let i = 0; i < responseBytes.length; i++) {
        if (responseBytes[i] !== expectedResponseBytes[i]) {
          return false;
        }
      }

      return true;
    } catch (error) {
      console.error('Error verifying key confirmation response:', error);
      return false;
    }
  }

  /**
   * Generates a unique challenge ID
   * @returns {string} A unique challenge identifier
   */
  generateChallengeId() {
    return `challenge_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Gets the session keys for an active session
   * @param {string} sessionId - The session ID
   * @returns {Object} The session keys
   */
  getSessionKeys(sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session || !session.keys) {
      throw new Error(`Session ${sessionId} not found or has no keys`);
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

    session.keys.messageCount++;
    // Combine IV seed with message counter to create unique IV
    const combined = new Uint8Array([...session.keys.ivSeed, ...new Uint8Array(new Uint32Array([session.keys.messageCount]).buffer)]);
    
    // Hash the combination to get a 12-byte IV (as required by AES-GCM)
    const hashBuffer = await window.crypto.subtle.digest("SHA-256", combined);
    return new Uint8Array(hashBuffer.slice(0, 12));  // 12 bytes for AES-GCM
  }
}

// Export the SimplifiedSecureKeyExchange class
export const secureKeyExchange = (userId) => new SimplifiedSecureKeyExchange(userId);