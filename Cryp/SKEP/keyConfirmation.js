/**
 * Key Confirmation Protocol Module
 * Implements HMAC challenge-response to verify both parties have the same session keys
 */

class KeyConfirmation {
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
   * Validates a key confirmation message
   * @param {Object} message - The received key confirmation message
   * @returns {boolean} Whether the message is valid
   */
  validateKeyConfirmationMessage(message) {
    try {
      if (!message || !message.type || !message.timestamp) {
        return false;
      }

      if (message.type === "KEY_CONFIRMATION_CHALLENGE") {
        if (!message.challenge || !message.challengeId) {
          return false;
        }

        // Validate challenge size (should be 32 bytes)
        if (message.challenge.length !== 32) {
          return false;
        }

        // Validate timestamp (not too old)
        if (Date.now() - message.timestamp > 60000) {  // 1 minute timeout
          return false;
        }

        return true;
      } else if (message.type === "KEY_CONFIRMATION_RESPONSE") {
        if (!message.response || !message.challengeId) {
          return false;
        }

        // Validate response size (HMAC-SHA256 should be 32 bytes)
        if (message.response.length !== 32) {
          return false;
        }

        // Validate timestamp (not too old)
        if (Date.now() - message.timestamp > 60000) {  // 1 minute timeout
          return false;
        }

        return true;
      }

      return false;
    } catch (error) {
      console.error('Error validating key confirmation message:', error);
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
   * Creates a session ready message to signal successful key exchange
   * @param {string} sessionId - The session ID
   * @returns {Object} The session ready message
   */
  createSessionReadyMessage(sessionId) {
    return {
      type: "SESSION_READY",
      sessionId: sessionId,
      timestamp: Date.now(),
      status: "confirmed"
    };
  }
}

// Export the KeyConfirmation class
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { KeyConfirmation };
} else {
  window.KeyConfirmation = KeyConfirmation;
}