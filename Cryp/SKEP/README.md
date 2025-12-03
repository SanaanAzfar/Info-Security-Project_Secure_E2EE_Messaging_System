# Secure Key Exchange Protocol (SKEP) Implementation

## Overview
This module implements a custom Secure Key Exchange Protocol as required for the Secure End-to-End Encrypted Messaging & File-Sharing System. The protocol combines ECDH key exchange with ECDSA signatures to prevent MITM attacks and uses HKDF for key derivation with HMAC-based confirmation.

## Protocol Design

### Core Security Properties
1. **Forward Secrecy** via ephemeral ECDH key exchange
2. **Authentication** via ECDSA digital signatures
3. **MITM Protection** via fingerprint verification and signed ephemeral keys
4. **Key Confirmation** via HMAC challenge-response mechanism
5. **Periodic Rekeying** for long-lived sessions

### Algorithm Stack (Web Crypto API Only)
- **ECDH with P-256 curve** (Key Exchange)
- **ECDSA with P-256 curve** (Digital Signatures)
- **HKDF with SHA-256** (Key Derivation)
- **HMAC with SHA-256** (Key Confirmation & Message Authentication)
- **AES-GCM with 256-bit keys** (Message Encryption)

## Protocol Flow

### Phase 1: Public Key Exchange
1. Alice sends her identity public keys (ECDH + ECDSA) to Bob
2. Bob responds with his identity public keys
3. Both parties verify fingerprints out-of-band

### Phase 2: Ephemeral Key Exchange
4. Alice generates ephemeral ECDH keypair and signs it with her identity ECDSA private key
5. Bob receives, verifies Alice's signature, and responds with his signed ephemeral key
6. Both parties perform ECDH to derive shared secret

### Phase 3: Session Key Derivation
7. HKDF is used to derive multiple session keys from shared secret:
   - Encryption key (AES-GCM)
   - HMAC confirmation key
   - Authentication key
   - IV seed for deterministic IV generation

### Phase 4: Key Confirmation
8. Alice sends HMAC challenge to Bob
9. Bob computes HMAC(response) with session key and sends back
10. Alice verifies response matches expected to confirm both have same keys
11. Session ready for secure communication

## Components

### 1. Protocol Initialization (`protocolInitialization.js`)
- Generates identity key pairs (ECDH for exchange, ECDSA for signatures)
- Creates verification fingerprints using SHA-256
- Formats fingerprints for human verification (hex, numeric, emoji)

### 2. Key Exchange Protocol (`keyExchangeProtocol.js`)
- Handles hello message exchange
- Manages ephemeral key generation and signing
- Verifies peer signatures to prevent MITM
- Validates protocol messages

### 3. Key Derivation (`keyDerivation.js`)
- Uses HKDF with SHA-256 to derive session keys
- Creates encryption, HMAC, and authentication keys
- Generates deterministic IVs from seed + counter
- Manages message counters

### 4. Key Confirmation (`keyConfirmation.js`)
- Implements HMAC challenge-response protocol
- Creates and validates confirmation messages
- Ensures both parties have identical session keys
- Detects MITM attacks during key exchange

### 5. Main Orchestrator (`secureKeyExchangeProtocol.js`)
- Combines all modules into complete protocol
- Manages sessions and state
- Handles complete key exchange workflow
- Provides API for external use

## Usage Example

```javascript
// Initialize the protocol
const skp = new SecureKeyExchangeProtocol("user123");
await skp.initialize();

// Start a key exchange with peer
const { sessionId, message: helloMessage } = await skp.startKeyExchange("peer456");

// Process a received hello message
const { sessionId, message: ephemeralMessage } = await skp.processHelloMessage(receivedHello);

// Process a received ephemeral message
const { message: confirmationMessage } = await skp.processEphemeralMessage(receivedEphemeral, sessionId);

// Process a received confirmation challenge
const { message: responseMessage } = await skp.processKeyConfirmationChallenge(receivedChallenge, sessionId);

// Process a received confirmation response
const result = await skp.processKeyConfirmationResponse(receivedResponse);

// Get session keys after confirmation
if (result.success) {
  const sessionKeys = skp.getSessionKeys(result.sessionId);
  // Now ready to encrypt/decrypt messages using sessionKeys
}
```

## Security Features

### MITM Attack Prevention
- Ephemeral keys are signed with long-term identity keys
- Out-of-band fingerprint verification available
- Key confirmation protocol ensures both parties have same keys

### Forward Secrecy
- Ephemeral keys are generated per session
- Keys are discarded after session ends
- Compromise of long-term keys doesn't compromise past sessions

### Key Confirmation
- HMAC challenge-response protocol
- Prevents downgrade and manipulation attacks
- Verifies key agreement between parties

## Compliance with Project Requirements

1. ✅ Uses ECDH with P-256 curve as required
2. ✅ Combines with digital signature mechanism (ECDSA)
3. ✅ Implements authenticity to prevent MITM attacks
4. ✅ Uses HKDF with SHA-256 for key derivation
5. ✅ Implements "Key Confirmation" message via HMAC challenge-response
6. ✅ Designed as custom variant, not textbook copy
7. ✅ Uses Web Crypto API as mandated
8. ✅ All crypto operations client-side only
9. ✅ No plaintext ever stored or transmitted
10. ✅ Implements 70%+ of cryptographic logic as required

## Message Types

- `KEY_EXCHANGE_HELLO`: Initial public key exchange
- `EPHEMERAL_KEY_EXCHANGE`: Signed ephemeral key exchange
- `KEY_CONFIRMATION_CHALLENGE`: HMAC challenge for confirmation
- `KEY_CONFIRMATION_RESPONSE`: HMAC response to challenge
- `SESSION_READY`: Confirmation of successful key exchange

## Error Handling

The implementation includes comprehensive error handling:
- Thorough input validation at each step
- MITM detection during signature verification
- Timeout handling for pending operations
- Proper cleanup of old sessions and challenges
- Detailed error messages for debugging

## Session Management

- Automatic session timeout and cleanup
- Session status tracking (initiated → keys_derived → confirmed)
- Session key management and rotation
- Message counter for deterministic IV generation