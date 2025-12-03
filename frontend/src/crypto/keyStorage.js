/**
 * Secure key storage utilities using IndexedDB and WebCrypto
 * Handles private key storage with encryption and secure key management
 * Private keys never leave the client device
 */

const DB_NAME = 'SecureMessagingKeys';
const DB_VERSION = 1;
const STORE_NAME = 'keys';

/**
 * Initialize IndexedDB for secure key storage
 * @returns {Promise<IDBDatabase>}
 */
function initDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
    
    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'id' });
      }
    };
  });
}

/**
 * Store encrypted private key in IndexedDB
 * @param {string} userId - User identifier
 * @param {CryptoKey} privateKey - Private key to store
 * @param {string} password - User password for key encryption
 * @returns {Promise<boolean>}
 */
export async function storePrivateKey(userId, privateKey, password) {
  try {
    const db = await initDB();
    
    // Export private key for storage
    const exportedKey = await window.crypto.subtle.exportKey('pkcs8', privateKey);
    
    // Derive encryption key from password
    const passwordKey = await deriveKeyFromPassword(password);
    
    // Encrypt the private key
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedKey = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      passwordKey,
      exportedKey
    );
    
    // Store in IndexedDB
    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    
    await new Promise((resolve, reject) => {
      const request = store.put({
        id: `private_key_${userId}`,
        encryptedKey: Array.from(new Uint8Array(encryptedKey)),
        iv: Array.from(iv),
        algorithm: privateKey.algorithm?.name || null,
        namedCurve: privateKey.algorithm?.namedCurve || 'P-384',
        timestamp: Date.now()
      });
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
    
    db.close();
    return true;
  } catch (error) {
    console.error('Failed to store private key:', error);
    throw new Error('Private key storage failed');
  }
}

/**
 * Retrieve and decrypt private key from IndexedDB
 * @param {string} userId - User identifier
 * @param {string} password - User password for key decryption
 * @returns {Promise<CryptoKey|null>}
 */
export async function retrievePrivateKey(userId, password) {
  try {
    const db = await initDB();
    const transaction = db.transaction([STORE_NAME], 'readonly');
    const store = transaction.objectStore(STORE_NAME);
    
    const keyData = await new Promise((resolve, reject) => {
      const request = store.get(`private_key_${userId}`);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    
    db.close();
    
    if (!keyData) {
      return null;
    }
    
    // Derive decryption key from password
    const passwordKey = await deriveKeyFromPassword(password);
    
    // Decrypt the private key
    const encryptedKey = new Uint8Array(keyData.encryptedKey);
    const iv = new Uint8Array(keyData.iv);
    
    const decryptedKey = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      passwordKey,
      encryptedKey
    );
    
    // Import the private key
    const algorithmName = keyData.algorithm
      || (userId.includes('_signing') ? 'ECDSA' : 'ECDH');
    const namedCurve = keyData.namedCurve || 'P-384';
    const importAlgorithm = { name: algorithmName, namedCurve };
    const usages = algorithmName === 'ECDSA' ? ['sign'] : ['deriveKey', 'deriveBits'];

    const privateKey = await window.crypto.subtle.importKey(
      'pkcs8',
      decryptedKey,
      importAlgorithm,
      false, // not extractable for security
      usages
    );
    
    return privateKey;
  } catch (error) {
    console.error('Failed to retrieve private key:', error);
    return null;
  }
}

/**
 * Store public key in IndexedDB (for caching)
 * @param {string} userId - User identifier (can be other users)
 * @param {CryptoKey} publicKey - Public key to store
 * @returns {Promise<boolean>}
 */
export async function storePublicKey(userId, publicKey) {
  try {
    const db = await initDB();
    
    // Export public key
    const exportedKey = await window.crypto.subtle.exportKey('raw', publicKey);
    
    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    
    await new Promise((resolve, reject) => {
      const request = store.put({
        id: `public_key_${userId}`,
        keyData: Array.from(new Uint8Array(exportedKey)),
        timestamp: Date.now()
      });
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
    
    db.close();
    return true;
  } catch (error) {
    console.error('Failed to store public key:', error);
    throw new Error('Public key storage failed');
  }
}

/**
 * Retrieve public key from IndexedDB
 * @param {string} userId - User identifier
 * @returns {Promise<CryptoKey|null>}
 */
export async function retrievePublicKey(userId) {
  try {
    const db = await initDB();
    const transaction = db.transaction([STORE_NAME], 'readonly');
    const store = transaction.objectStore(STORE_NAME);
    
    const keyData = await new Promise((resolve, reject) => {
      const request = store.get(`public_key_${userId}`);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    
    db.close();
    
    if (!keyData) {
      return null;
    }
    
    // Import public key
    const keyBytes = new Uint8Array(keyData.keyData);
    const publicKey = await window.crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'ECDH', namedCurve: 'P-384' },
      false,
      []
    );
    
    return publicKey;
  } catch (error) {
    console.error('Failed to retrieve public key:', error);
    return null;
  }
}

/**
 * Delete stored keys for a user (for logout/cleanup)
 * @param {string} userId - User identifier
 * @returns {Promise<boolean>}
 */
export async function deleteUserKeys(userId) {
  try {
    const db = await initDB();
    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    
    await Promise.all([
      new Promise((resolve, reject) => {
        const request = store.delete(`private_key_${userId}`);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      }),
      new Promise((resolve, reject) => {
        const request = store.delete(`public_key_${userId}`);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      })
    ]);
    
    db.close();
    return true;
  } catch (error) {
    console.error('Failed to delete user keys:', error);
    return false;
  }
}

/**
 * Derive encryption key from user password using PBKDF2
 * @param {string} password - User password
 * @param {Uint8Array} salt - Salt for key derivation (optional)
 * @returns {Promise<CryptoKey>}
 */
async function deriveKeyFromPassword(password, salt) {
  if (!salt) {
    salt = new TextEncoder().encode('SecureMessagingApp2024Salt');
  }
  
  // Import password as base key
  const baseKey = await window.crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  
  // Derive AES key from password
  const derivedKey = await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000, // High iteration count for security
      hash: 'SHA-256'
    },
    baseKey,
    {
      name: 'AES-GCM',
      length: 256
    },
    false, // not extractable
    ['encrypt', 'decrypt']
  );
  
  return derivedKey;
}