/**
 * Protocol Initialization Module for Secure Key Exchange Protocol
 * Handles identity key generation and fingerprint creation for MITM protection
 */

class ProtocolInitialization {
  /**
   * Generates identity key pairs for the user (ECDH for key exchange, ECDSA for signatures)
   * @param {string} userId - The user identifier
   * @returns {Promise<Object>} Object containing the identity key pairs
   */
  async generateIdentityKeys(userId) {
    try {
      // Generate ECDH keypair for key exchange (uses P-256 as required)
      const ecdhKeyPair = await window.crypto.subtle.generateKey(
        {
          name: "ECDH",
          namedCurve: "P-256"  // 256-bit security level as required
        },
        true,  // extractable (for export)
        ["deriveKey", "deriveBits"]  // key usage
      );

      // Generate ECDSA keypair for digital signatures (uses P-256 as required)
      const ecdsaKeyPair = await window.crypto.subtle.generateKey(
        {
          name: "ECDSA",
          namedCurve: "P-256"  // Matching curve for consistency
        },
        true,  // extractable
        ["sign", "verify"]  // key usage
      );

      return {
        userId: userId,
        ecdhKeyPair: ecdhKeyPair,
        ecdsaKeyPair: ecdsaKeyPair,
        generatedAt: Date.now()
      };
    } catch (error) {
      throw new Error(`Identity key generation failed: ${error.message}`);
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
        emoji: this.formatEmojiCode(hashArray),

        // QR code data
        qrData: {
          ecdh: Array.from(new Uint8Array(ecdhBytes)),
          ecdsa: Array.from(new Uint8Array(ecdsaBytes)),
          fingerprint: hashArray
        }
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
}

// Export the ProtocolInitialization class
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { ProtocolInitialization };
} else {
  window.ProtocolInitialization = ProtocolInitialization;
}