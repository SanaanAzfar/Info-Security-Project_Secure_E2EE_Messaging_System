/**
 * Key Management Integration for Frontend
 * Integrates the Key Generation & Secure Key Storage module into the frontend
 */

// Import the key management modules from the Cryp directory
// Since these are not in the same directory, we'll need to reference them appropriately
// For now, we'll implement this as a standalone module that can be imported

class FrontendKeyManager {
  constructor() {
    // Initialize the key management system
    this.keyManagement = null;
    this.isInitialized = false;
  }

  /**
   * Initializes the key management system
   * @param {string} userId - The current user's ID
   * @returns {Promise<void>}
   */
  async initialize(userId) {
    if (typeof window !== 'undefined' && window.KeyManagement) {
      this.keyManagement = new window.KeyManagement();
      this.isInitialized = true;
    } else {
      // If window.KeyManagement is not available, we'll need to implement a fallback
      // or wait for the modules to be loaded
      throw new Error('KeyManagement module not available in the browser scope');
    }
  }

  /**
   * Generates and stores a new key pair for the user
   * @param {string} userId - The user's ID
   * @returns {Promise<Object>} The generated key pair
   */
  async generateAndStoreKeys(userId) {
    if (!this.isInitialized) {
      await this.initialize(userId);
    }

    return await this.keyManagement.generateAndStoreKeyPair(userId);
  }

  /**
   * Retrieves the user's key pair from storage
   * @param {string} userId - The user's ID
   * @returns {Promise<Object>} The stored key pair
   */
  async retrieveKeys(userId) {
    if (!this.isInitialized) {
      await this.initialize(userId);
    }

    return await this.keyManagement.retrieveKeyPair(userId);
  }

  /**
   * Checks if keys exist for the user
   * @param {string} userId - The user's ID
   * @returns {Promise<boolean>} Whether keys exist for the user
   */
  async hasKeysStored(userId) {
    if (!this.isInitialized) {
      await this.initialize(userId);
    }

    return await this.keyManagement.hasKeysStored(userId);
  }

  /**
   * Removes keys for a user
   * @param {string} userId - The user's ID
   * @returns {Promise<void>}
   */
  async removeKeys(userId) {
    if (!this.isInitialized) {
      await this.initialize(userId);
    }

    return await this.keyManagement.removeKeys(userId);
  }

  /**
   * Gets a user's public key for sharing
   * @param {string} userId - The user's ID
   * @returns {Promise<CryptoKey>} The public key
   */
  async getUserPublicKey(userId) {
    if (!this.isInitialized) {
      await this.initialize(userId);
    }

    return await this.keyManagement.getUserPublicKey(userId);
  }

  /**
   * Exports a key for transmission
   * @param {CryptoKey} key - The key to export
   * @param {string} keyType - 'public' or 'private'
   * @returns {Promise<string>} The exported key string
   */
  async exportKeyForTransmission(key, keyType) {
    if (!this.isInitialized) {
      await this.initialize('temp');
    }

    return await this.keyManagement.exportKeyForTransmission(key, keyType);
  }

  /**
   * Imports a key from transmission
   * @param {string} serializedKey - The serialized key string
   * @param {string} keyType - 'public' or 'private'
   * @param {Array<string>} keyUsages - The key usages
   * @returns {Promise<CryptoKey>} The imported key
   */
  async importKeyFromTransmission(serializedKey, keyType, keyUsages) {
    if (!this.isInitialized) {
      await this.initialize('temp');
    }

    return await this.keyManagement.importKeyFromTransmission(serializedKey, keyType, keyUsages);
  }
}

// If we want to create a simplified version that directly uses the Web Crypto API
// based on the requirements in the project, here's a streamlined implementation
// that's more appropriate for the frontend:

/**
 * Simplified Key Management for Frontend
 * Implements RSA key pair generation and secure storage
 */
export class SimplifiedKeyManager {
  constructor() {
    this.keySize = 2048; // Minimum 2048 bits as per requirements
    this.indexedDBName = 'SecureKeyStorage';
    this.indexedDBVersion = 1;
    this.objectStoreName = 'privateKeys';
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
   * Opens the IndexedDB database for private key storage
   * @returns {Promise<IDBDatabase>} The opened database
   */
  async openDB() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.indexedDBName, this.indexedDBVersion);

      request.onerror = () => {
        reject(new Error(`Database error: ${request.error}`));
      };

      request.onsuccess = () => {
        resolve(request.result);
      };

      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        
        // Create an object store for private keys if it doesn't exist
        if (!db.objectStoreNames.contains(this.objectStoreName)) {
          const objectStore = db.createObjectStore(this.objectStoreName, { keyPath: 'userId' });
          // Add an index for searching by userId
          objectStore.createIndex('userId', 'userId', { unique: true });
        }
      };
    });
  }

  /**
   * Stores a private key in IndexedDB
   * @param {string} userId - The user identifier
   * @param {CryptoKey} privateKey - The private key to store
   * @returns {Promise<void>}
   */
  async storePrivateKey(userId, privateKey) {
    try {
      const db = await this.openDB();
      
      // Export the private key to JWK format to store it
      const exportedPrivateKey = await window.crypto.subtle.exportKey('jwk', privateKey);
      
      // Create a transaction
      const transaction = db.transaction([this.objectStoreName], 'readwrite');
      const objectStore = transaction.objectStore(this.objectStoreName);
      
      // Store the key with the userId as key
      const data = {
        userId: userId,
        privateKey: exportedPrivateKey,
        timestamp: new Date().toISOString()
      };
      
      const request = objectStore.put(data);
      
      return new Promise((resolve, reject) => {
        request.onsuccess = () => {
          resolve();
        };
        
        request.onerror = () => {
          reject(new Error(`Failed to store private key: ${request.error}`));
        };
      });
    } catch (error) {
      throw new Error(`Error storing private key: ${error.message}`);
    }
  }

  /**
   * Retrieves a private key from IndexedDB
   * @param {string} userId - The user identifier
   * @returns {Promise<CryptoKey|null>} The retrieved private key or null if not found
   */
  async retrievePrivateKey(userId) {
    try {
      const db = await this.openDB();
      
      // Create a transaction
      const transaction = db.transaction([this.objectStoreName], 'readonly');
      const objectStore = transaction.objectStore(this.objectStoreName);
      
      // Get the stored key data
      const request = objectStore.get(userId);
      
      return new Promise((resolve, reject) => {
        request.onsuccess = async () => {
          const result = request.result;
          if (result && result.privateKey) {
            // Import the stored private key back to CryptoKey format
            const privateKey = await window.crypto.subtle.importKey(
              'jwk',
              result.privateKey,
              {
                name: 'RSA-OAEP',
                hash: { name: "SHA-256" }
              },
              true, // extractable
              ['decrypt'] // appropriate key usages
            );
            resolve(privateKey);
          } else {
            resolve(null);
          }
        };
        
        request.onerror = () => {
          reject(new Error(`Failed to retrieve private key: ${request.error}`));
        };
      });
    } catch (error) {
      throw new Error(`Error retrieving private key: ${error.message}`);
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
   * @returns {Promise<Object>} Object containing the generated keys
   */
  async generateAndStoreKeys(userId) {
    try {
      // Generate a new key pair
      const { publicKey, privateKey } = await this.generateKeyPair();

      // Store the private key securely in IndexedDB
      await this.storePrivateKey(userId, privateKey);

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
   * @returns {Promise<Object>} Object containing both keys
   */
  async retrieveKeys(userId) {
    try {
      const privateKey = await this.retrievePrivateKey(userId);
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
      const privateKey = await this.retrievePrivateKey(userId);
      const publicKey = await this.retrievePublicKey(userId);

      return !!(privateKey && publicKey);
    } catch {
      return false;
    }
  }
}

// Create a single instance for export
export const keyManager = new SimplifiedKeyManager();

// For compatibility with the original KeyManagement module, if it's available
export const frontendKeyManager = typeof window !== 'undefined' && window.KeyManagement ? 
  new FrontendKeyManager() : 
  null;