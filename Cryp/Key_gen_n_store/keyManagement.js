/**
 * Main Key Management Module for Secure E2E Messaging System
 * Combines key generation, secure storage, and utility functions
 * Ensures private keys never leave the client device
 */

// Import the individual modules
// Note: In a browser environment, these would be included via script tags
// In Node.js environment, we would use require statements

class KeyManagement {
  constructor() {
    // Initialize the required modules
    this.keyGenerator = new window.KeyGenerator ? new window.KeyGenerator() : 
                       (typeof KeyGenerator !== 'undefined' ? new KeyGenerator() : null);
    this.secureKeyStorage = new window.SecureKeyStorage ? new window.SecureKeyStorage() :
                           (typeof SecureKeyStorage !== 'undefined' ? new SecureKeyStorage() : null);
    this.publicKeyStorage = new window.PublicKeyStorage ? new window.PublicKeyStorage() :
                           (typeof PublicKeyStorage !== 'undefined' ? new PublicKeyStorage() : null);
    this.keyUtils = new window.KeyUtils ? new window.KeyUtils() :
                    (typeof KeyUtils !== 'undefined' ? new KeyUtils() : null);
    
    if (!this.keyGenerator || !this.secureKeyStorage || !this.publicKeyStorage || !this.keyUtils) {
      throw new Error('Missing required modules for KeyManagement');
    }
  }

  /**
   * Generates a new key pair and stores it securely
   * @param {string} userId - The user identifier
   * @returns {Promise<Object>} Object containing the generated keys
   */
  async generateAndStoreKeyPair(userId) {
    try {
      // Validate input
      if (!userId || typeof userId !== 'string' || userId.trim() === '') {
        throw new Error('Valid userId is required');
      }

      // Generate a new key pair
      const { publicKey, privateKey } = await this.keyGenerator.generateKeyPair();

      // Store the private key securely in IndexedDB
      await this.secureKeyStorage.storePrivateKey(userId, privateKey);

      // Store the public key in localStorage
      await this.publicKeyStorage.storePublicKey(userId, publicKey);

      return {
        publicKey: publicKey,
        privateKey: privateKey // Note: This is the in-memory key, not stored anywhere else
      };
    } catch (error) {
      console.error('Error in generateAndStoreKeyPair:', error);
      throw new Error(`Key pair generation and storage failed: ${error.message}`);
    }
  }

  /**
   * Retrieves a user's key pair from storage
   * @param {string} userId - The user identifier
   * @returns {Promise<Object>} Object containing public and private keys (if available)
   */
  async retrieveKeyPair(userId) {
    try {
      // Validate input
      if (!userId || typeof userId !== 'string' || userId.trim() === '') {
        throw new Error('Valid userId is required');
      }

      // Retrieve the private key from IndexedDB
      const privateKey = await this.secureKeyStorage.retrievePrivateKey(userId);

      // Retrieve the public key from localStorage
      const publicKey = await this.publicKeyStorage.retrievePublicKey(userId);

      return {
        publicKey: publicKey,
        privateKey: privateKey
      };
    } catch (error) {
      console.error('Error in retrieveKeyPair:', error);
      throw new Error(`Key pair retrieval failed: ${error.message}`);
    }
  }

  /**
   * Checks if a user already has keys stored
   * @param {string} userId - The user identifier
   * @returns {Promise<boolean>} True if keys exist, false otherwise
   */
  async hasKeysStored(userId) {
    try {
      // Check if either key exists (they should both exist, but check both for safety)
      const privateKey = await this.secureKeyStorage.retrievePrivateKey(userId);
      const publicKey = await this.publicKeyStorage.retrievePublicKey(userId);

      return !!(privateKey && publicKey);
    } catch (error) {
      console.warn('Error checking if keys are stored:', error);
      return false;
    }
  }

  /**
   * Removes keys for a user from storage
   * @param {string} userId - The user identifier
   * @returns {Promise<void>}
   */
  async removeKeys(userId) {
    try {
      // Validate input
      if (!userId || typeof userId !== 'string' || userId.trim() === '') {
        throw new Error('Valid userId is required');
      }

      // Remove private key from IndexedDB
      await this.secureKeyStorage.deletePrivateKey(userId);

      // Remove public key from localStorage
      await this.publicKeyStorage.deletePublicKey(userId);
    } catch (error) {
      console.error('Error in removeKeys:', error);
      throw new Error(`Key removal failed: ${error.message}`);
    }
  }

  /**
   * Gets a user's public key for sharing
   * @param {string} userId - The user identifier
   * @returns {Promise<CryptoKey>} The public key
   */
  async getUserPublicKey(userId) {
    try {
      // Validate input
      if (!userId || typeof userId !== 'string' || userId.trim() === '') {
        throw new Error('Valid userId is required');
      }

      // Retrieve the public key from localStorage
      const publicKey = await this.publicKeyStorage.retrievePublicKey(userId);

      if (!publicKey) {
        throw new Error(`No public key found for user: ${userId}`);
      }

      return publicKey;
    } catch (error) {
      console.error('Error in getUserPublicKey:', error);
      throw new Error(`Public key retrieval failed: ${error.message}`);
    }
  }

  /**
   * Exports a key in a format suitable for network transmission
   * @param {CryptoKey} key - The key to export
   * @param {string} keyType - 'public' or 'private'
   * @returns {Promise<string>} The exported key as a string
   */
  async exportKeyForTransmission(key, keyType) {
    try {
      if (!key || !keyType) {
        throw new Error('Key and keyType are required for export');
      }

      if (keyType !== 'public' && keyType !== 'private') {
        throw new Error('keyType must be either "public" or "private"');
      }

      // Use the key utils to serialize the key
      return await this.keyUtils.serializeKeyForTransmission(key, keyType);
    } catch (error) {
      console.error('Error in exportKeyForTransmission:', error);
      throw new Error(`Key export for transmission failed: ${error.message}`);
    }
  }

  /**
   * Imports a key from a network transmission format
   * @param {string} serializedKey - The serialized key string
   * @param {string} keyType - 'public' or 'private'
   * @param {Array<string>} keyUsages - The intended key usages
   * @returns {Promise<CryptoKey>} The imported key
   */
  async importKeyFromTransmission(serializedKey, keyType, keyUsages) {
    try {
      if (!serializedKey || !keyType || !keyUsages) {
        throw new Error('serializedKey, keyType, and keyUsages are required for import');
      }

      if (keyType !== 'public' && keyType !== 'private') {
        throw new Error('keyType must be either "public" or "private"');
      }

      if (!Array.isArray(keyUsages) || keyUsages.length === 0) {
        throw new Error('keyUsages must be a non-empty array');
      }

      // Use the key utils to deserialize the key
      return await this.keyUtils.deserializeKeyFromTransmission(serializedKey, keyType, keyUsages);
    } catch (error) {
      console.error('Error in importKeyFromTransmission:', error);
      throw new Error(`Key import from transmission failed: ${error.message}`);
    }
  }

  /**
   * Validates that a key is of the expected type and has required usages
   * @param {CryptoKey} key - The key to validate
   * @param {Array<string>} requiredUsages - The required key usages
   * @param {string} expectedType - Expected key type ('public' or 'private')
   * @returns {boolean} True if the key is valid, false otherwise
   */
  validateKey(key, requiredUsages, expectedType) {
    try {
      if (!key) {
        console.warn('Key validation failed: key is null or undefined');
        return false;
      }

      if (key.type !== expectedType) {
        console.warn(`Key validation failed: expected type ${expectedType}, got ${key.type}`);
        return false;
      }

      // Check that all required usages are present
      for (const usage of requiredUsages) {
        if (!key.usages.includes(usage)) {
          console.warn(`Key validation failed: missing usage ${usage}`);
          return false;
        }
      }

      return true;
    } catch (error) {
      console.error('Error in validateKey:', error);
      return false;
    }
  }

  /**
   * Gets the list of users with stored keys
   * @returns {Promise<Array<string>>} List of user IDs with stored keys
   */
  async listUsersWithKeys() {
    try {
      // Get users with private keys stored (which should correspond to those with public keys too)
      const privateKeysUsers = await this.secureKeyStorage.listStoredKeys();
      
      // We could also check public keys to make sure both exist, but typically if private exists,
      // public should exist too, since they are generated together
      return privateKeysUsers;
    } catch (error) {
      console.error('Error in listUsersWithKeys:', error);
      throw new Error(`Listing users with keys failed: ${error.message}`);
    }
  }
}

// Export the KeyManagement class
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { KeyManagement };
} else {
  window.KeyManagement = KeyManagement;
}