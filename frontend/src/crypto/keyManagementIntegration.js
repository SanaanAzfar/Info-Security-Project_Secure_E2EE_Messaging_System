/**
 * Key Management Integration for Frontend
 * Integrates secure key storage with password-based encryption for private keys
 */

// Import the existing key storage utilities
import { storePrivateKey, retrievePrivateKey } from './keyStorage.js';

/**
 * Simplified Key Management for Frontend with Secure Storage
 * Implements RSA key pair generation and secure storage with password-based encryption
 */
export class SimplifiedKeyManager {
  constructor() {
    this.keySize = 2048; // Minimum 2048 bits as per requirements
  }

  /**
   * Generates RSA key pair using Web Crypto API
   * @returns {Promise<Object>} Object containing public and private keys
   */
  async generateKeyPair() {
    try {
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
   * Stores a private key in IndexedDB with password-based encryption
   * @param {string} userId - The user identifier
   * @param {CryptoKey} privateKey - The private key to store
   * @param {string} password - The user's password for encryption
   * @returns {Promise<void>}
   */
  async storePrivateKey(userId, privateKey, password) {
    try {
      // Use the existing keyStorage utility which handles password-based encryption
      await storePrivateKey(userId, privateKey, password);
    } catch (error) {
      throw new Error(`Error storing private key: ${error.message}`);
    }
  }

  /**
   * Retrieves and decrypts a private key from IndexedDB
   * @param {string} userId - The user identifier
   * @param {string} password - The user's password for decryption
   * @returns {Promise<CryptoKey|null>} The retrieved private key or null if not found
   */
  async retrievePrivateKey(userId, password) {
    try {
      // Use the existing keyStorage utility which handles password-based decryption
      return await retrievePrivateKey(userId, password);
    } catch (error) {
      console.error('Error retrieving private key:', error);
      return null; // Return null on error rather than throwing to maintain compatibility
    }
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
      const storageKey = 'publicKey_' + userId;
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
      const storageKey = 'publicKey_' + userId;
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
   * Generates and stores keys for a user
   * @param {string} userId - The user identifier
   * @param {string} password - The user's password for encrypting private key
   * @returns {Promise<Object>} Object containing the generated keys
   */
  async generateAndStoreKeys(userId, password) {
    try {
      // Generate a new key pair
      const { publicKey, privateKey } = await this.generateKeyPair();

      // Store the private key securely in IndexedDB with password encryption
      await this.storePrivateKey(userId, privateKey, password);

      // Store the public key in localStorage
      await this.storePublicKey(userId, publicKey);

      return {
        publicKey: publicKey,
        privateKey: privateKey
      };
    } catch (error) {
      throw new Error(`Key generation and storage failed: ${error.message}`);
    }
  }

  /**
   * Retrieves both public and private keys for a user
   * @param {string} userId - The user identifier
   * @param {string} password - The user's password for decrypting private key
   * @returns {Promise<Object>} Object containing both keys
   */
  async retrieveKeys(userId, password) {
    try {
      const privateKey = await this.retrievePrivateKey(userId, password);
      const publicKey = await this.retrievePublicKey(userId);

      return {
        publicKey: publicKey,
        privateKey: privateKey
      };
    } catch (error) {
      throw new Error(`Key retrieval failed: ${error.message}`);
    }
  }

  /**
   * Checks if keys exist for a user
   * @param {string} userId - The user identifier
   * @returns {Promise<boolean>} Whether keys exist
   */
  async hasKeysStored(userId) {
    try {
      // Check if public key exists (since we store public keys in localStorage)
      const publicKey = this.retrievePublicKey(userId);
      // We can't check if private key exists without the password,
      // so just check for public key existence
      return !!publicKey;
    } catch {
      return false;
    }
  }
}

// Create a single instance for export
export const keyManager = new SimplifiedKeyManager();