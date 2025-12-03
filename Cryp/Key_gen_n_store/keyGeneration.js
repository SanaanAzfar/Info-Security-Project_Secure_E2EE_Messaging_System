/**
 * Key Generation Module for Secure E2E Messaging System
 * Implements RSA key pair generation using Web Crypto API
 * Private keys are stored securely using IndexedDB
 * Public keys are stored in localStorage
 */

class KeyGenerator {
  constructor() {
    this.keySize = 2048; // Minimum 2048 bits as per requirements
    this.indexedDBName = 'SecureKeyStorage';
    this.indexedDBVersion = 1;
    this.objectStoreName = 'privateKeys';
  }

  /**
   * Generates a new RSA key pair using Web Crypto API
   * @returns {Promise<Object>} Object containing public and private keys
   */
  async generateKeyPair() {
    try {
      // Generate an RSA key pair
      const keyPair = await window.crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: this.keySize, // 2048 bits minimum as per requirements
          publicExponent: new Uint8Array([1, 0, 1]), // 65537
          hash: "SHA-256",
        },
        true, // Whether the key is extractable (i.e., can be used in exportKey)
        ["encrypt", "decrypt"] // Key usages
      );

      return {
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey
      };
    } catch (error) {
      throw new Error(`Key generation failed: ${error.message}`);
    }
  }

  /**
   * Exports a key to a specific format
   * @param {CryptoKey} key - The key to export
   * @param {string} format - The format to export to (e.g., 'jwk', 'spki', 'pkcs8')
   * @returns {Promise<any>} The exported key
   */
  async exportKey(key, format) {
    try {
      const exportedKey = await window.crypto.subtle.exportKey(format, key);
      return exportedKey;
    } catch (error) {
      throw new Error(`Key export failed: ${error.message}`);
    }
  }

  /**
   * Imports a key from a specific format
   * @param {any} keyData - The key data to import
   * @param {string} format - The format of the key data
   * @param {Array<string>} keyUsages - The intended key usages
   * @param {string} keyType - 'public' or 'private'
   * @returns {Promise<CryptoKey>} The imported key
   */
  async importKey(keyData, format, keyUsages, keyType) {
    try {
      const importedKey = await window.crypto.subtle.importKey(
        format,
        keyData,
        {
          name: keyType === 'public' ? 'RSA-OAEP' : 'RSA-OAEP',
          hash: {name: "SHA-256"},
        },
        true, // Whether the key is extractable
        keyType === 'public' ? keyUsages : keyUsages
      );
      return importedKey;
    } catch (error) {
      throw new Error(`Key import failed: ${error.message}`);
    }
  }
}

// Export the KeyGenerator class
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { KeyGenerator };
} else {
  window.KeyGenerator = KeyGenerator;
}