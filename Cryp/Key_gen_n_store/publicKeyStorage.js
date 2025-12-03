/**
 * Public Key Storage Module using localStorage
 * Public keys are stored in localStorage as they can be shared openly
 */

class PublicKeyStorage {
  constructor() {
    this.storageKeyPrefix = 'publicKey_';
  }

  /**
   * Stores a public key in localStorage
   * @param {string} userId - The user identifier
   * @param {CryptoKey} publicKey - The public key to store
   * @returns {Promise<void>}
   */
  async storePublicKey(userId, publicKey) {
    try {
      // Export the public key to JWK format to store it
      const exportedPublicKey = await window.crypto.subtle.exportKey('jwk', publicKey);
      
      // Convert the key to JSON string for storage
      const keyData = JSON.stringify(exportedPublicKey);
      
      // Store in localStorage with a unique key
      const storageKey = this.storageKeyPrefix + userId;
      localStorage.setItem(storageKey, keyData);
    } catch (error) {
      throw new Error(`Error storing public key: ${error.message}`);
    }
  }

  /**
   * Retrieves a public key from localStorage
   * @param {string} userId - The user identifier
   * @returns {Promise<CryptoKey|null>} The retrieved public key or null if not found
   */
  async retrievePublicKey(userId) {
    try {
      // Get the stored key data
      const storageKey = this.storageKeyPrefix + userId;
      const keyData = localStorage.getItem(storageKey);
      
      if (!keyData) {
        return null;
      }
      
      // Parse the stored JSON
      const exportedPublicKey = JSON.parse(keyData);
      
      // Import the stored public key back to CryptoKey format
      const publicKey = await window.crypto.subtle.importKey(
        'jwk',
        exportedPublicKey,
        {
          name: 'RSA-OAEP',
          hash: { name: "SHA-256" }
        },
        true, // extractable
        ['encrypt'] // appropriate key usages
      );
      
      return publicKey;
    } catch (error) {
      throw new Error(`Error retrieving public key: ${error.message}`);
    }
  }

  /**
   * Deletes a public key from localStorage
   * @param {string} userId - The user identifier
   * @returns {Promise<void>}
   */
  async deletePublicKey(userId) {
    try {
      // Remove the key from localStorage
      const storageKey = this.storageKeyPrefix + userId;
      localStorage.removeItem(storageKey);
    } catch (error) {
      throw new Error(`Error deleting public key: ${error.message}`);
    }
  }

  /**
   * Lists all stored public key user IDs
   * @returns {Promise<Array<string>>} List of user IDs that have stored public keys
   */
  async listStoredPublicKeys() {
    try {
      const userIds = [];
      const prefix = this.storageKeyPrefix;
      
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && key.startsWith(prefix)) {
          const userId = key.substring(prefix.length);
          userIds.push(userId);
        }
      }
      
      return userIds;
    } catch (error) {
      throw new Error(`Error listing stored public keys: ${error.message}`);
    }
  }

  /**
   * Gets the storage key for a given userId
   * @param {string} userId - The user identifier
   * @returns {string} The storage key
   */
  getStorageKey(userId) {
    return this.storageKeyPrefix + userId;
  }
}

// Export the PublicKeyStorage class
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { PublicKeyStorage };
} else {
  window.PublicKeyStorage = PublicKeyStorage;
}