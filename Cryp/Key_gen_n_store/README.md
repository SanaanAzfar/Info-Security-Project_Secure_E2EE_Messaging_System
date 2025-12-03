# Key Generation & Secure Key Storage Module

## Overview
This module implements the Key Generation & Secure Key Storage component of the Secure End-to-End Encrypted Messaging & File-Sharing System, as specified in the project requirements.

## Components

### 1. Key Generation (`keyGeneration.js`)
- Implements RSA key pair generation using Web Crypto API
- Generates 2048-bit RSA keys as per security requirements (minimum 2048 bits)
- Uses RSA-OAEP algorithm with SHA-256 hash
- Supports both encryption and decryption key usages

### 2. Secure Key Storage (`secureKeyStorage.js`)
- Stores private keys securely using IndexedDB
- Private keys are stored in JWK (JSON Web Key) format
- Private keys never leave the client device
- Provides methods to store, retrieve, and delete private keys
- Uses user ID as the key in IndexedDB

### 3. Public Key Storage (`publicKeyStorage.js`)
- Stores public keys in localStorage
- Public keys can be safely stored and shared openly
- Stores keys in JWK format
- Provides methods to store, retrieve, and delete public keys

### 4. Key Utilities (`keyUtils.js`)
- Provides utility functions for key export/import in various formats
- Supports JWK (JSON Web Key) and SPKI formats
- Includes serialization/deserialization for network transmission
- Converts between ArrayBuffer and Base64 formats

### 5. Key Management (`keyManagement.js`)
- Main module that combines all functionality
- Provides high-level API for key operations
- Implements error handling and validation
- Handles complete key lifecycle (generation, storage, retrieval, deletion)

## Security Features

### Private Key Protection
- Private keys are stored only in IndexedDB on the client device
- Private keys are never transmitted to the server
- Private keys are stored in encrypted format (JWK) in IndexedDB

### Public Key Handling
- Public keys are stored in localStorage as they can be shared openly
- Public keys can be shared with other users for encryption

### Key Formats
- Uses JWK (JSON Web Key) format for internal storage
- Uses SPKI format for public key transmission
- Supports serialization for network transmission

## Usage Example

```javascript
// Initialize key management system
const keyManager = new KeyManagement();

// Generate and store a new key pair for a user
const userId = "user123";
const keyPair = await keyManager.generateAndStoreKeyPair(userId);

// Retrieve key pair for a user later
const storedKeyPair = await keyManager.retrieveKeyPair(userId);

// Export a public key for sharing with another user
const publicKey = await keyManager.getUserPublicKey(userId);
const exportedPublicKey = await keyManager.exportKeyForTransmission(publicKey, 'public');

// Import a public key received from another user
const importedPublicKey = await keyManager.importKeyFromTransmission(exportedPublicKey, 'public', ['encrypt']);
```

## Compliance with Project Requirements

1. ✅ Asymmetric key pair generated on registration (RSA-2048 as required)
2. ✅ Private keys never stored on server - stored only in IndexedDB on client
3. ✅ Uses Web Crypto API as required
4. ✅ Uses IndexedDB for secure storage as required
5. ✅ All encryption occurs client-side
6. ✅ Private keys never leave the client device
7. ✅ No plaintext storage or transmission

## Technical Constraints Satisfied

- RSA key size: 2048 bits (minimum required)
- Uses Web Crypto API (SubtleCrypto) as mandated
- Uses IndexedDB for secure storage as allowed
- Private keys stored only on client device
- Implementation uses native Web Crypto API, no third-party crypto libraries