/**
 * File encryption utilities for secure end-to-end encrypted file sharing
 * Supports chunked encryption for large files using AES-256-GCM
 * Files are encrypted on the client before upload to server
 */

import { generateIV, arrayBufferToBase64, base64ToArrayBuffer } from './encryption.js';

const CHUNK_SIZE = 1024 * 1024; // 1MB chunks for large files

/**
 * Encrypt a file using AES-256-GCM with chunking support
 * @param {File} file - File object to encrypt
 * @param {CryptoKey} sessionKey - Session key for encryption
 * @returns {Promise<{encryptedChunks: Array, metadata: Object}>}
 */
export async function encryptFile(file, sessionKey) {
  try {
    const chunks = [];
    const fileSize = file.size;
    const totalChunks = Math.ceil(fileSize / CHUNK_SIZE);
    
    // Generate file-specific IV and metadata
    const fileId = generateFileId();
    const masterIV = generateIV();
    
    for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
      const start = chunkIndex * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, fileSize);
      const chunk = file.slice(start, end);
      
      // Read chunk as ArrayBuffer
      const chunkBuffer = await chunk.arrayBuffer();
      
      // Generate unique IV for each chunk by combining master IV with chunk index
      const chunkIV = new Uint8Array(12);
      chunkIV.set(masterIV.slice(0, 8));
      chunkIV.set(new Uint8Array(new Uint32Array([chunkIndex]).buffer), 8);
      
      // Encrypt chunk
      const encryptedChunk = await window.crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: chunkIV,
          tagLength: 128,
        },
        sessionKey,
        chunkBuffer
      );
      
      // Split encrypted chunk into ciphertext and auth tag
      const ciphertext = encryptedChunk.slice(0, -16);
      const authTag = encryptedChunk.slice(-16);
      
      chunks.push({
        chunkIndex,
        ciphertext: arrayBufferToBase64(ciphertext),
        authTag: arrayBufferToBase64(authTag),
        iv: arrayBufferToBase64(chunkIV.buffer),
        size: chunkBuffer.byteLength
      });
    }
    
    const metadata = {
      fileId,
      originalName: file.name,
      originalSize: fileSize,
      mimeType: file.type,
      totalChunks,
      chunkSize: CHUNK_SIZE,
      masterIV: arrayBufferToBase64(masterIV.buffer),
      timestamp: Date.now()
    };
    
    return { encryptedChunks: chunks, metadata };
  } catch (error) {
    console.error('File encryption failed:', error);
    throw new Error('File encryption failed');
  }
}

/**
 * Decrypt a file from encrypted chunks
 * @param {Array} encryptedChunks - Array of encrypted chunk objects
 * @param {Object} metadata - File metadata
 * @param {CryptoKey} sessionKey - Session key for decryption
 * @returns {Promise<Blob>} - Decrypted file as Blob
 */
export async function decryptFile(encryptedChunks, metadata, sessionKey) {
  try {
    const decryptedChunks = [];
    
    // Sort chunks by index to ensure proper order
    const sortedChunks = encryptedChunks.sort((a, b) => a.chunkIndex - b.chunkIndex);
    
    for (const chunk of sortedChunks) {
      // Convert base64 back to ArrayBuffer
      const ciphertext = base64ToArrayBuffer(chunk.ciphertext);
      const authTag = base64ToArrayBuffer(chunk.authTag);
      const iv = new Uint8Array(base64ToArrayBuffer(chunk.iv));
      
      // Combine ciphertext and auth tag for GCM decryption
      const combined = new Uint8Array(ciphertext.byteLength + authTag.byteLength);
      combined.set(new Uint8Array(ciphertext), 0);
      combined.set(new Uint8Array(authTag), ciphertext.byteLength);
      
      // Decrypt chunk
      const decryptedChunk = await window.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv,
          tagLength: 128,
        },
        sessionKey,
        combined
      );
      
      decryptedChunks.push(decryptedChunk);
    }
    
    // Combine all decrypted chunks into a single Blob
    const decryptedFile = new Blob(decryptedChunks, { type: metadata.mimeType });
    
    return decryptedFile;
  } catch (error) {
    console.error('File decryption failed:', error);
    throw new Error('File decryption failed - file may be corrupted');
  }
}

/**
 * Encrypt a small file (under 10MB) in a single operation
 * @param {File} file - File to encrypt
 * @param {CryptoKey} sessionKey - Session key for encryption
 * @returns {Promise<{encryptedData: string, metadata: Object}>}
 */
export async function encryptSmallFile(file, sessionKey) {
  try {
    if (file.size > 10 * 1024 * 1024) {
      throw new Error('File too large for single encryption - use chunked encryption');
    }
    
    const fileBuffer = await file.arrayBuffer();
    const iv = generateIV();
    const fileId = generateFileId();
    
    const encrypted = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128,
      },
      sessionKey,
      fileBuffer
    );
    
    const metadata = {
      fileId,
      originalName: file.name,
      originalSize: file.size,
      mimeType: file.type,
      iv: arrayBufferToBase64(iv.buffer),
      timestamp: Date.now(),
      isChunked: false
    };
    
    return {
      encryptedData: arrayBufferToBase64(encrypted),
      metadata
    };
  } catch (error) {
    console.error('Small file encryption failed:', error);
    throw new Error('Small file encryption failed');
  }
}

/**
 * Decrypt a small file (single chunk)
 * @param {string} encryptedData - Base64 encoded encrypted data
 * @param {Object} metadata - File metadata
 * @param {CryptoKey} sessionKey - Session key for decryption
 * @returns {Promise<Blob>} - Decrypted file as Blob
 */
export async function decryptSmallFile(encryptedData, metadata, sessionKey) {
  try {
    const encryptedBuffer = base64ToArrayBuffer(encryptedData);
    const iv = new Uint8Array(base64ToArrayBuffer(metadata.iv));
    
    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128,
      },
      sessionKey,
      encryptedBuffer
    );
    
    return new Blob([decrypted], { type: metadata.mimeType });
  } catch (error) {
    console.error('Small file decryption failed:', error);
    throw new Error('Small file decryption failed');
  }
}

/**
 * Generate a unique file ID
 * @returns {string} - Unique file identifier
 */
function generateFileId() {
  return `file_${Date.now()}_${Math.random().toString(36).substring(2)}`;
}

/**
 * Validate file metadata
 * @param {Object} metadata - File metadata to validate
 * @returns {boolean} - True if metadata is valid
 */
export function validateFileMetadata(metadata) {
  const requiredFields = ['fileId', 'originalName', 'originalSize', 'mimeType', 'timestamp'];
  
  for (const field of requiredFields) {
    if (!(field in metadata)) {
      return false;
    }
  }
  
  // Validate file size limits
  if (metadata.originalSize > 100 * 1024 * 1024) { // 100MB limit
    return false;
  }
  
  // Validate timestamp (not too old, not in future)
  const now = Date.now();
  const age = now - metadata.timestamp;
  if (age < 0 || age > 24 * 60 * 60 * 1000) { // 24 hours
    return false;
  }
  
  return true;
}

/**
 * Progress tracking for file operations
 */
export class FileProgressTracker {
  constructor() {
    this.callbacks = new Map();
  }
  
  /**
   * Set progress callback for a file operation
   * @param {string} fileId - File identifier
   * @param {Function} callback - Progress callback function
   */
  setProgressCallback(fileId, callback) {
    this.callbacks.set(fileId, callback);
  }
  
  /**
   * Update progress for a file operation
   * @param {string} fileId - File identifier
   * @param {number} processed - Number of chunks processed
   * @param {number} total - Total number of chunks
   */
  updateProgress(fileId, processed, total) {
    const callback = this.callbacks.get(fileId);
    if (callback) {
      const progress = (processed / total) * 100;
      callback(progress, processed, total);
    }
  }
  
  /**
   * Clear progress tracking for a file
   * @param {string} fileId - File identifier
   */
  clearProgress(fileId) {
    this.callbacks.delete(fileId);
  }
}

// Export singleton progress tracker
export const fileProgressTracker = new FileProgressTracker();