/**
 * Index file for the Secure Key Exchange Protocol (SKEP) Module
 * Provides a single entry point to import all SKEP functionality
 */

// Import all SKEP modules
import { ProtocolInitialization } from './protocolInitialization.js';
import { KeyExchangeProtocol } from './keyExchangeProtocol.js';
import { KeyDerivation } from './keyDerivation.js';
import { KeyConfirmation } from './keyConfirmation.js';
import { SecureKeyExchangeProtocol } from './secureKeyExchangeProtocol.js';

// Export all classes for easy import
export {
  ProtocolInitialization,
  KeyExchangeProtocol,
  KeyDerivation,
  KeyConfirmation,
  SecureKeyExchangeProtocol
};

// For browser environments, attach to window object if not in module context
if (typeof window !== 'undefined' && typeof module === 'undefined') {
  window.ProtocolInitialization = ProtocolInitialization;
  window.KeyExchangeProtocol = KeyExchangeProtocol;
  window.KeyDerivation = KeyDerivation;
  window.KeyConfirmation = KeyConfirmation;
  window.SecureKeyExchangeProtocol = SecureKeyExchangeProtocol;
}