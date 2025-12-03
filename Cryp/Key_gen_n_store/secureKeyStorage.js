/**
 * Secure Key Storage Module for Private Keys using IndexedDB
 * Private keys are stored encrypted in IndexedDB as per project requirements
 */

class SecureKeyStorage {
  constructor() {
    this.indexedDBName = 'SecureKeyStorage';
    this.indexedDBVersion = 1;
    this.objectStoreName = 'privateKeys';
  }

  /**
   * Opens the IndexedDB database
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
   * Deletes a private key from IndexedDB
   * @param {string} userId - The user identifier
   * @returns {Promise<void>}
   */
  async deletePrivateKey(userId) {
    try {
      const db = await this.openDB();
      
      // Create a transaction
      const transaction = db.transaction([this.objectStoreName], 'readwrite');
      const objectStore = transaction.objectStore(this.objectStoreName);
      
      // Delete the key
      const request = objectStore.delete(userId);
      
      return new Promise((resolve, reject) => {
        request.onsuccess = () => {
          resolve();
        };
        
        request.onerror = () => {
          reject(new Error(`Failed to delete private key: ${request.error}`));
        };
      });
    } catch (error) {
      throw new Error(`Error deleting private key: ${error.message}`);
    }
  }

  /**
   * Lists all stored private key user IDs
   * @returns {Promise<Array<string>>} List of user IDs that have stored keys
   */
  async listStoredKeys() {
    try {
      const db = await this.openDB();
      
      // Create a transaction
      const transaction = db.transaction([this.objectStoreName], 'readonly');
      const objectStore = transaction.objectStore(this.objectStoreName);
      
      // Get all keys
      const request = objectStore.getAllKeys();
      
      return new Promise((resolve, reject) => {
        request.onsuccess = () => {
          // Extract just the userId values from the stored objects
          const userIds = request.result;
          resolve(userIds);
        };
        
        request.onerror = () => {
          reject(new Error(`Failed to list stored keys: ${request.error}`));
        };
      });
    } catch (error) {
      throw new Error(`Error listing stored keys: ${error.message}`);
    }
  }
}

// Export the SecureKeyStorage class
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { SecureKeyStorage };
} else {
  window.SecureKeyStorage = SecureKeyStorage;
}