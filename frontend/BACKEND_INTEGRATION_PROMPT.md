# Backend Integration Guide for Secure E2EE Messaging System

**ROLE: Backend Developer**  
**PROJECT: End-to-End Encrypted Messaging System**  
**INTEGRATION TARGET: React Frontend with Web Crypto API**

This document provides comprehensive guidance for backend developers to integrate with the secure messaging frontend. The frontend implements client-side encryption using Web Crypto API and expects specific API contracts from the backend.

---

## 🔁 **Message Sequencing & Deduplication Contract**

1. **Conversation counters**: Track one `sequenceNumber` counter per `(senderId, receiverId)` tuple (or per conversation). Increment it for every stored outbound message.
2. **Canonical metadata**: Persist the server-approved `messageId`, `sequenceNumber`, and `timestamp`. Always replay that same triplet in REST history and WebSocket events.
3. **Single delivery**: Emit exactly one `message_received` event per persisted message per receiver. On reconnect, re-stream only the messages the client missed (sorted ascending by `sequenceNumber`).
4. **Server timestamps**: Use server time for `timestamp` so both participants see consistent ordering. Keep servers NTP-synchronized to avoid frontend rejections.
5. **Replay defense**: Reject duplicate `sequenceNumber` submissions or stale `nonce` values to keep anti-replay guarantees intact.

---
## 📋 **PROJECT OVERVIEW**

The frontend is a React application that handles:
- ✅ Client-side key generation (ECC P-256/P-384)
- ✅ End-to-end message encryption (AES-256-GCM)
- ✅ Secure file encryption before upload
- ✅ Key exchange protocol (ECDH)
- ✅ Digital signatures for authentication
- ✅ Replay attack protection

**Backend Responsibilities:**
- User authentication and session management
- Encrypted message storage and delivery
- Encrypted file storage and delivery
- Key exchange coordination
- Real-time communication via WebSocket
- User management and contact system

### Frontend Expectations Snapshot
| Concern | Requirement |
| --- | --- |
| Message identity | Every persisted/emitted message needs a globally unique `id` string. The React client deduplicates by this value. |
| Sequencing | Maintain a monotonic `sequenceNumber` per `(senderId, receiverId)` pair. Include it in REST responses and WebSocket payloads. |
| Payload fidelity | `ciphertext`, `iv`, `authTag`, `nonce`, and `timestamp` must remain exactly as sent by the originating client. |
| Clock skew | Frontend rejects payloads older than 5 minutes; keep backend clocks accurate (±60 s) or provide NTP sync. |
| Event delivery | Emit `message_received` exactly once per message per receiver. Replays after reconnect should send only missed items, in order. |
| Key exchange state | Preserve exchange metadata so reconnecting clients can finish ECDH without re-registering. |

---

## 🔐 **SECURITY ARCHITECTURE**

### Key Management Flow
1. **Registration**: Frontend generates ECC key pair, sends ONLY public key to backend
2. **Private Keys**: NEVER stored on server, remain on client in IndexedDB
3. **Session Keys**: Derived via ECDH, exist only in client memory
4. **Message Encryption**: All encryption/decryption happens on frontend

### Data Flow
```
Client A → Encrypt Message → Backend (stores encrypted) → Client B → Decrypt Message
```

**CRITICAL**: Backend never sees plaintext messages or private keys!

---

## 🌐 **REQUIRED API ENDPOINTS**

### 1. **AUTHENTICATION ENDPOINTS**

#### **POST /api/auth/register**
**Purpose**: Register new user with their public key

**Request Body**:
```json
{
  "email": "user@example.com",
  "username": "john_doe",
  "password": "hashedPassword123!",
  "publicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----"
}
```

**Response** (201 Created):
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "user_123",
    "email": "user@example.com",
    "username": "john_doe",
    "publicKey": "-----BEGIN PUBLIC KEY-----\n...",
    "createdAt": "2025-12-03T10:30:00Z"
  }
}
```

**Validation Requirements**:
- Email: Valid format, unique
- Username: Alphanumeric + underscore, 3-30 chars, unique
- Password: Hash before storing (bcrypt recommended)
- Public Key: Valid PEM format ECC P-256/P-384

---

#### **POST /api/auth/login**
**Purpose**: Authenticate user and return contacts

**Request Body**:
```json
{
  "email": "user@example.com",
  "password": "plainTextPassword"
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "user_123",
    "email": "user@example.com",
    "username": "john_doe",
    "publicKey": "-----BEGIN PUBLIC KEY-----\n..."
  },
  "contacts": [
    {
      "id": "user_456",
      "username": "jane_smith",
      "publicKey": "-----BEGIN PUBLIC KEY-----\n...",
      "lastSeen": "2025-12-03T09:15:00Z"
    }
  ]
}
```

---

#### **POST /api/auth/logout**
**Purpose**: Invalidate user session

**Headers**:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response** (200 OK):
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

---

### 2. **USER MANAGEMENT ENDPOINTS**

#### **GET /api/users/profile**
**Purpose**: Get current user profile

**Headers**:
```
Authorization: Bearer <token>
```

**Response** (200 OK):
```json
{
  "user": {
    "id": "user_123",
    "email": "user@example.com",
    "username": "john_doe",
    "publicKey": "-----BEGIN PUBLIC KEY-----\n...",
    "createdAt": "2025-12-03T10:30:00Z",
    "lastLogin": "2025-12-03T11:45:00Z"
  }
}
```

---

#### **GET /api/users/contacts**
**Purpose**: Get user's contact list

**Headers**:
```
Authorization: Bearer <token>
```

**Response** (200 OK):
```json
{
  "contacts": [
    {
      "id": "user_456",
      "username": "jane_smith",
      "publicKey": "-----BEGIN PUBLIC KEY-----\n...",
      "addedAt": "2025-12-01T14:20:00Z",
      "lastSeen": "2025-12-03T09:15:00Z",
      "isOnline": true
    }
  ]
}
```

---

#### **POST /api/users/add-contact**
**Purpose**: Add new contact by username

**Headers**:
```
Authorization: Bearer <token>
```

**Request Body**:
```json
{
  "username": "jane_smith"
}
```

**Response** (201 Created):
```json
{
  "success": true,
  "contact": {
    "id": "user_456",
    "username": "jane_smith",
    "publicKey": "-----BEGIN PUBLIC KEY-----\n...",
    "addedAt": "2025-12-03T12:00:00Z"
  }
}
```

---

### 3. **KEY EXCHANGE ENDPOINTS**

#### **POST /api/keyexchange/initiate**
**Purpose**: Initiate secure key exchange between users

**Headers**:
```
Authorization: Bearer <token>
```

**Request Body**:
```json
{
  "targetUserId": "user_456",
  "ephemeralPublicKey": "-----BEGIN PUBLIC KEY-----\n...",
  "signature": "base64SignatureString..."
}
```

**Response** (201 Created):
```json
{
  "success": true,
  "exchangeId": "exchange_789",
  "status": "pending"
}
```

---

#### **POST /api/keyexchange/respond**
**Purpose**: Respond to key exchange request

**Headers**:
```
Authorization: Bearer <token>
```

**Request Body**:
```json
{
  "exchangeId": "exchange_789",
  "ephemeralPublicKey": "-----BEGIN PUBLIC KEY-----\n...",
  "signature": "base64SignatureString..."
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "confirmed": true,
  "status": "completed"
}
```

---

### 4. **MESSAGING ENDPOINTS**

#### **GET /api/messages/:contactId**
**Purpose**: Retrieve message history with specific contact

**Headers**:
```
Authorization: Bearer <token>
```

**Query Parameters**:
```
?limit=50&offset=0&before=messageId
```

**Response** (200 OK):
```json
{
  "messages": [
    {
      "id": "msg_001",
      "senderId": "user_123",
      "receiverId": "user_456",
      "encryptedContent": "base64EncryptedContent...",
      "iv": "base64IV...",
      "authTag": "base64AuthTag...",
      "nonce": "base64Nonce...",
      "timestamp": "2025-12-03T11:30:00Z",
      "signature": "base64Signature...",
      "messageType": "text"
    }
  ],
  "hasMore": false,
  "total": 25
}
```

---

#### **POST /api/messages/send**
**Purpose**: Send encrypted message

**Headers**:
```
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body**:
```json
{
  "receiverId": "user_456",
  "encryptedContent": "base64EncryptedContent...",
  "iv": "base64IV...",
  "authTag": "base64AuthTag...",
  "nonce": "base64Nonce...",
  "timestamp": "2025-12-03T12:00:00Z",
  "signature": "base64Signature...",
  "messageType": "text",
  "sequenceNumber": 42
}
```

**Response** (201 Created):
```json
{
  "success": true,
  "messageId": "msg_002",
  "timestamp": "2025-12-03T12:00:00Z",
  "sequenceNumber": 42
}
```

> **Sequence enforcement**: The backend should validate the incoming `sequenceNumber` or assign the next number server-side. Persist the final value and reuse it for every REST/WebSocket response so clients stay aligned.

---

### 5. **FILE SHARING ENDPOINTS**

#### **POST /api/files/upload**
**Purpose**: Upload encrypted file

**Headers**:
```
Authorization: Bearer <token>
Content-Type: multipart/form-data
```

**Form Data**:
```
receiverId: user_456
filename: document.pdf (original name)
encryptedData: <binary encrypted file data>
iv: base64IV...
authTag: base64AuthTag...
signature: base64Signature...
```

**Response** (201 Created):
```json
{
  "success": true,
  "fileId": "file_789",
  "downloadUrl": "/api/files/file_789",
  "uploadedAt": "2025-12-03T12:05:00Z"
}
```

---

#### **GET /api/files/:fileId**
**Purpose**: Download encrypted file

**Headers**:
```
Authorization: Bearer <token>
```

**Response** (200 OK):
```
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="encrypted_file"
<binary encrypted file data>
```

---

## 🔄 **WEBSOCKET EVENTS**

### Connection
```javascript
// Client connects with authentication
socket.emit('authenticate', { token: 'Bearer eyJ...' })
```

### **Incoming Events** (Backend → Frontend)

#### **message_received**
```json
{
  "messageId": "msg_003",
  "senderId": "user_456",
  "receiverId": "user_123",
  "encryptedContent": "base64Content...",
  "iv": "base64IV...",
  "authTag": "base64AuthTag...",
  "nonce": "base64Nonce...",
  "timestamp": "2025-12-03T12:10:00Z",
  "signature": "base64Signature...",
  "messageType": "text",
  "sequenceNumber": 58
}
```

#### **key_exchange_request**
```json
{
  "exchangeId": "exchange_790",
  "fromUserId": "user_456",
  "ephemeralPublicKey": "-----BEGIN PUBLIC KEY-----\n...",
  "signature": "base64Signature..."
}
```

#### **key_exchange_response**
```json
{
  "exchangeId": "exchange_790",
  "fromUserId": "user_456",
  "ephemeralPublicKey": "-----BEGIN PUBLIC KEY-----\n...",
  "signature": "base64Signature...",
  "status": "completed"
}
```

#### **user_online** / **user_offline**
```json
{
  "userId": "user_456",
  "status": "online",
  "lastSeen": "2025-12-03T12:15:00Z"
}
```

#### **typing_indicator**
```json
{
  "fromUserId": "user_456",
  "toUserId": "user_123",
  "isTyping": true
}
```

### **Outgoing Events** (Frontend → Backend)

#### **join_room**
```json
{
  "userId": "user_123"
}
```

#### **send_message**
```json
{
  "receiverId": "user_456",
  "encryptedContent": "base64Content...",
  "iv": "base64IV...",
  "authTag": "base64AuthTag...",
  "nonce": "base64Nonce...",
  "timestamp": "2025-12-03T12:20:00Z",
  "signature": "base64Signature...",
  "messageType": "text",
  "sequenceNumber": 5
}
```

> The backend may normalize the payload (generate `messageId`, adjust `sequenceNumber`) but must echo the finalized record via REST and WebSocket so the frontend can reconcile state after reconnects.

#### **typing_start** / **typing_stop**
```json
{
  "contactId": "user_456"
}
```

---

## 🗄️ **DATABASE SCHEMA RECOMMENDATIONS**

### **users** table
```sql
CREATE TABLE users (
  id VARCHAR(50) PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  username VARCHAR(50) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  public_key TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_login TIMESTAMP,
  is_active BOOLEAN DEFAULT TRUE
);
```

### **messages** table
```sql
CREATE TABLE messages (
  id VARCHAR(50) PRIMARY KEY,
  sender_id VARCHAR(50) NOT NULL,
  receiver_id VARCHAR(50) NOT NULL,
  sequence_number BIGINT NOT NULL,
  encrypted_content TEXT NOT NULL,
  iv VARCHAR(255) NOT NULL,
  auth_tag VARCHAR(255) NOT NULL,
  nonce VARCHAR(255) NOT NULL,
  signature TEXT NOT NULL,
  message_type VARCHAR(20) DEFAULT 'text',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (sender_id) REFERENCES users(id),
  FOREIGN KEY (receiver_id) REFERENCES users(id),
  UNIQUE(sender_id, receiver_id, sequence_number)
);
```

### **contacts** table
```sql
CREATE TABLE contacts (
  id VARCHAR(50) PRIMARY KEY,
  user_id VARCHAR(50) NOT NULL,
  contact_user_id VARCHAR(50) NOT NULL,
  added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, contact_user_id),
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (contact_user_id) REFERENCES users(id)
);
```

### **key_exchanges** table
```sql
CREATE TABLE key_exchanges (
  id VARCHAR(50) PRIMARY KEY,
  initiator_id VARCHAR(50) NOT NULL,
  target_id VARCHAR(50) NOT NULL,
  initiator_ephemeral_key TEXT,
  target_ephemeral_key TEXT,
  initiator_signature TEXT,
  target_signature TEXT,
  status ENUM('pending', 'completed', 'failed') DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  completed_at TIMESTAMP NULL,
  FOREIGN KEY (initiator_id) REFERENCES users(id),
  FOREIGN KEY (target_id) REFERENCES users(id)
);
```

### **files** table
```sql
CREATE TABLE files (
  id VARCHAR(50) PRIMARY KEY,
  uploader_id VARCHAR(50) NOT NULL,
  receiver_id VARCHAR(50) NOT NULL,
  original_filename VARCHAR(255) NOT NULL,
  encrypted_filename VARCHAR(255) NOT NULL,
  file_size BIGINT NOT NULL,
  iv VARCHAR(255) NOT NULL,
  auth_tag VARCHAR(255) NOT NULL,
  signature TEXT NOT NULL,
  storage_path VARCHAR(500) NOT NULL,
  uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (uploader_id) REFERENCES users(id),
  FOREIGN KEY (receiver_id) REFERENCES users(id)
);
```

---

## ⚠️ **CRITICAL SECURITY REQUIREMENTS**

### 1. **NEVER Store Plaintext**
- Messages are encrypted on frontend, store only encrypted content
- Files are encrypted on frontend, store only encrypted files
- Private keys NEVER reach the backend

### 2. **Authentication & Authorization**
- Implement JWT token validation middleware
- Token expiration and refresh mechanism
- Rate limiting on all endpoints
- CORS configuration for frontend domain

### 3. **Input Validation**
- Validate all request bodies against schemas
- Sanitize file uploads
- Prevent SQL injection
- Validate public key formats

### 4. **Message Integrity**
- Store all encryption metadata (IV, auth tags, signatures)
- Implement message sequencing for replay protection
- Validate timestamps (reject messages older than 5 minutes)

### 5. **File Security**
- Store files outside web root
- Implement file access controls
- Validate file types and sizes
- Secure file cleanup policies

---

## 🚀 **IMPLEMENTATION CHECKLIST**

### Phase 1: Core Authentication
- [ ] User registration with public key storage
- [ ] JWT-based authentication
- [ ] Password hashing (bcrypt)
- [ ] Token validation middleware

### Phase 2: Messaging System
- [ ] Message storage with encryption metadata
- [ ] Message retrieval with pagination
- [ ] Real-time WebSocket setup
- [ ] Message delivery confirmation & sequence enforcement

### Phase 3: Contact Management
- [ ] User search and discovery
- [ ] Contact addition/removal
- [ ] Online status tracking
- [ ] Contact synchronization

### Phase 4: Key Exchange
- [ ] Key exchange request handling
- [ ] Signature verification
- [ ] Exchange status tracking
- [ ] Real-time key exchange events

### Phase 5: File Sharing
- [ ] Encrypted file upload
- [ ] Secure file storage
- [ ] File download with access control
- [ ] File metadata management

### Phase 6: Security & Performance
- [ ] Rate limiting
- [ ] Request validation
- [ ] Error handling
- [ ] Logging and monitoring
- [ ] Database optimization
- [ ] Memory management

---

## 📝 **TESTING ENDPOINTS**

Use tools like Postman or curl to test integration:

```bash
# Register user
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "username": "testuser",
    "password": "TestPass123!",
    "publicKey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
  }'

# Login
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPass123!"
  }'

# Get messages (with token)
curl -X GET http://localhost:3000/api/messages/user_456 \
  -H "Authorization: Bearer your_jwt_token_here"
```

---

## 🔧 **FRONTEND INTEGRATION NOTES**

### API Base URL Configuration
Frontend expects environment variable:
```env
VITE_API_BASE_URL=http://localhost:3000/api
VITE_WS_URL=ws://localhost:3000
```

### Error Response Format
Frontend expects consistent error format:
```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid email format",
    "details": {
      "field": "email",
      "value": "invalid-email"
    }
  }
}
```

### CORS Configuration
```javascript
app.use(cors({
  origin: 'http://localhost:5173', // Frontend URL
  credentials: true
}));
```

---

## 📞 **SUPPORT & COMMUNICATION**

### Frontend Team Contact
- **Project Lead**: [Frontend Developer Name]
- **Repository**: Frontend implementation complete
- **Documentation**: See `frontend/README.md`

### Integration Testing
- Setup local development environment
- Test with sample encrypted data
- Validate WebSocket connections
- Verify key exchange protocol

### Questions & Issues
1. **Authentication**: How to handle token refresh?
2. **File Storage**: Preferred cloud storage service?
3. **Database**: MongoDB vs PostgreSQL preference?
4. **Scaling**: Message queue for high-volume messaging?
5. **Monitoring**: Preferred logging and monitoring tools?

---

**IMPORTANT**: This frontend implementation prioritizes security over convenience. All cryptographic operations happen client-side, ensuring zero-knowledge architecture where the backend never accesses plaintext data or private keys.