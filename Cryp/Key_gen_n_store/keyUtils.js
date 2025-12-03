/**
 * Key Utility Module
 * Provides functions to export/import keys in various formats
 */

class KeyUtils {
  /**
   * Exports a key to JWK (JSON Web Key) format
   * @param {CryptoKey} key - The key to export
   * @returns {Promise<Object>} The exported key in JWK format
   */
  static async exportKeyToJWK(key) {
    try {
      const exportedKey = await window.crypto.subtle.exportKey('jwk', key);
      return exportedKey;
    } catch (error) {
      throw new Error(`JWK export failed: ${error.message}`);
    }
  }

  /**
   * Imports a key from JWK format
   * @param {Object} jwkKey - The JWK formatted key data
   * @param {Array<string>} keyUsages - The intended key usages
   * @param {string} keyType - 'public' or 'private'
   * @returns {Promise<CryptoKey>} The imported key
   */
  static async importKeyFromJWK(jwkKey, keyUsages, keyType) {
    try {
      const importedKey = await window.crypto.subtle.importKey(
        'jwk',
        jwkKey,
        {
          name: 'RSA-OAEP',
          hash: { name: "SHA-256" }
        },
        true, // extractable
        keyType === 'public' ? keyUsages : keyUsages
      );
      return importedKey;
    } catch (error) {
      throw new Error(`JWK import failed: ${error.message}`);
    }
  }

  /**
   * Exports a public key to SPKI format (for network transmission)
   * @param {CryptoKey} publicKey - The public key to export
   * @returns {Promise<ArrayBuffer>} The exported key in SPKI format
   */
  static async exportPublicKeyToSPKI(publicKey) {
    try {
      const exportedKey = await window.crypto.subtle.exportKey('spki', publicKey);
      return exportedKey;
    } catch (error) {
      throw new Error(`SPKI export failed: ${error.message}`);
    }
  }

  /**
   * Imports a public key from SPKI format
   * @param {ArrayBuffer} spkiKey - The SPKI formatted key data
   * @returns {Promise<CryptoKey>} The imported public key
   */
  static async importPublicKeyFromSPKI(spkiKey) {
    try {
      const importedKey = await window.crypto.subtle.importKey(
        'spki',
        spkiKey,
        {
          name: 'RSA-OAEP',
          hash: { name: "SHA-256" }
        },
        true, // extractable
        ['encrypt'] // only encrypt usage for public keys
      );
      return importedKey;
    } catch (error) {
      throw new Error(`SPKI import failed: ${error.message}`);
    }
  }

  /**
   * Converts ArrayBuffer to Base64 string (useful for network transmission)
   * @param {ArrayBuffer} buffer - The buffer to convert
   * @returns {string} The Base64 encoded string
   */
  static arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Converts Base64 string to ArrayBuffer
   * @param {string} base64 - The Base64 string to convert
   * @returns {ArrayBuffer} The converted buffer
   */
  static base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Serializes a key for transmission over network
   * @param {CryptoKey} key - The key to serialize
   * @param {string} keyType - 'public' or 'private'
   * @returns {Promise<string>} The serialized key as a Base64 string
   */
  static async serializeKeyForTransmission(key, keyType) {
    if (keyType === 'public') {
      const spkiKey = await this.exportPublicKeyToSPKI(key);
      return this.arrayBufferToBase64(spkiKey);
    } else {
      // For private keys, export as JWK, then serialize
      const jwkKey = await this.exportKeyToJWK(key);
      return btoa(JSON.stringify(jwkKey));
    }
  }

  /**
   * Deserializes a key from network transmission
   * @param {string} serializedKey - The serialized key as Base64 string
   * @param {string} keyType - 'public' or 'private'
   * @param {Array<string>} keyUsages - The intended key usages
   * @returns {Promise<CryptoKey>} The deserialized key
   */
  static async deserializeKeyFromTransmission(serializedKey, keyType, keyUsages) {
    if (keyType === 'public') {
      const spkiBuffer = this.base64ToArrayBuffer(serializedKey);
      return await this.importPublicKeyFromSPKI(spkiBuffer);
    } else {
      // For private keys, first deserialize JWK from string
      const jwkStr = atob(serializedKey);
      const jwkKey = JSON.parse(jwkStr);
      return await this.importKeyFromJWK(jwkKey, keyUsages, 'private');
    }
  }
}

// Export the KeyUtils class
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { KeyUtils };
} else {
  window.KeyUtils = KeyUtils;
}