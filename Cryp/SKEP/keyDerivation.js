/**
 * Key Derivation Module for Secure Key Exchange Protocol
 * Implements HKDF-based session key derivation from shared secret
 */

class KeyDerivation {
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
   * Generates a random salt for HKDF
   * @param {number} length - Length of the salt in bytes (default 32 bytes)
   * @returns {Promise<ArrayBuffer>} The generated salt
   */
  async generateSalt(length = 32) {
    try {
      const salt = window.crypto.getRandomValues(new Uint8Array(length));
      return salt.buffer;
    } catch (error) {
      throw new Error(`Salt generation failed: ${error.message}`);
    }
  }

  /**
   * Generates a deterministic IV for AES-GCM encryption
   * Uses the IV seed and a counter to ensure uniqueness
   * @param {Uint8Array} ivSeed - The IV seed from key derivation
   * @param {number} counter - The message counter
   * @returns {Uint8Array} The generated IV (12 bytes for AES-GCM)
   */
  generateDeterministicIV(ivSeed, counter) {
    try {
      // Combine IV seed with message counter to create unique IV
      const combined = new Uint8Array([...ivSeed, ...new Uint8Array(new Uint32Array([counter]).buffer)]);
      
      // Hash the combination to get a 12-byte IV (as required by AES-GCM)
      const hashBuffer = window.crypto.subtle.digestSync ? 
        window.crypto.subtle.digestSync("SHA-256", combined) : 
        window.crypto.subtle.digest("SHA-256", combined);
      
      // For sync operation, we'll use a Web Crypto approach that's async but then resolve
      // Since we need sync here, we'll use a different approach
      const hashArray = Array.from(new Uint8Array(hashBuffer.slice(0, 12)));
      return new Uint8Array(hashArray);
    } catch (error) {
      throw new Error(`IV generation failed: ${error.message}`);
    }
  }

  /**
   * Async version of generateDeterministicIV to properly use Web Crypto API
   * @param {Uint8Array} ivSeed - The IV seed from key derivation
   * @param {number} counter - The message counter
   * @returns {Promise<Uint8Array>} The generated IV (12 bytes for AES-GCM)
   */
  async generateDeterministicIVAsync(ivSeed, counter) {
    try {
      // Combine IV seed with message counter to create unique IV
      const combined = new Uint8Array([...ivSeed, ...new Uint8Array(new Uint32Array([counter]).buffer)]);
      
      // Hash the combination to get a 12-byte IV (as required by AES-GCM)
      const hashBuffer = await window.crypto.subtle.digest("SHA-256", combined);
      return new Uint8Array(hashBuffer.slice(0, 12));  // 12 bytes for AES-GCM
    } catch (error) {
      throw new Error(`IV generation failed: ${error.message}`);
    }
  }

  /**
   * Updates the message counter and returns the next IV
   * @param {Object} sessionKeys - The session keys object
   * @returns {Promise<Uint8Array>} The next IV to use
   */
  async getNextIV(sessionKeys) {
    try {
      sessionKeys.messageCount++;
      return await this.generateDeterministicIVAsync(sessionKeys.ivSeed, sessionKeys.messageCount);
    } catch (error) {
      throw new Error(`Next IV generation failed: ${error.message}`);
    }
  }

  /**
   * Validates the derived keys
   * @param {Object} keys - The derived keys object
   * @returns {boolean} Whether the keys are valid
   */
  validateKeys(keys) {
    try {
      if (!keys || !keys.encryptionKey || !keys.hmacKey || !keys.authKey) {
        return false;
      }

      // Check that keys have the expected properties
      if (typeof keys.derivedAt !== 'number' || 
          !keys.ivSeed || 
          typeof keys.messageCount !== 'number') {
        return false;
      }

      return true;
    } catch (error) {
      console.error('Error validating keys:', error);
      return false;
    }
  }
}

// Export the KeyDerivation class
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { KeyDerivation };
} else {
  window.KeyDerivation = KeyDerivation;
}