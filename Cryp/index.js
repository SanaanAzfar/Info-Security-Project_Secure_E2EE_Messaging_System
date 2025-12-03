/**
 * Index file for the Key Generation & Secure Key Storage Module
 * Provides a single entry point to import all key management functionality
 */

// This file serves as the main entry point for the key management system
// It allows importing all functionality with a single import statement

// Import all modules
import { KeyGenerator } from './keyGeneration.js';
import { SecureKeyStorage } from './secureKeyStorage.js';
import { PublicKeyStorage } from './publicKeyStorage.js';
import { KeyUtils } from './keyUtils.js';
import { KeyManagement } from './keyManagement.js';

// Export all classes for easy import
export {
  KeyGenerator,
  SecureKeyStorage,
  PublicKeyStorage,
  KeyUtils,
  KeyManagement
};

// For browser environments, attach to window object if not in module context
if (typeof window !== 'undefined' && typeof module === 'undefined') {
  window.KeyGenerator = KeyGenerator;
  window.SecureKeyStorage = SecureKeyStorage;
  window.PublicKeyStorage = PublicKeyStorage;
  window.KeyUtils = KeyUtils;
  window.KeyManagement = KeyManagement;
}