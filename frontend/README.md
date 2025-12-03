# Secure End-to-End Encrypted Messaging System - Frontend

A React-based frontend application implementing end-to-end encryption for secure messaging and file sharing.

## 🔐 Security Features

- **ECC P-256/P-384 Key Generation** - Generates asymmetric key pairs during registration
- **ECDH Key Exchange** - Secure session key establishment
- **AES-256-GCM Encryption** - Message and file encryption
- **Digital Signatures** - Message authenticity verification
- **Replay Attack Protection** - Nonce and timestamp validation
- **MITM Protection** - Signature verification for key exchange
- **Secure Storage** - Private keys stored in IndexedDB with WebCrypto

## 🚀 Quick Start

### Prerequisites
- Node.js 16+ 
- npm or yarn

### Installation
```bash
cd frontend
npm install
npm run dev
```

The application will be available at `http://localhost:5173`

## 📁 Project Structure

```
src/
├── components/          # React UI components
│   ├── Auth.css        # Authentication styling
│   ├── Chat.css        # Chat interface styling
│   ├── ChatInterface.jsx
│   ├── FileUpload.css  # File upload styling
│   ├── FileUpload.jsx  # Encrypted file upload
│   ├── LoginForm.jsx   # User login form
│   └── RegisterForm.jsx # User registration form
├── crypto/             # Cryptographic utilities
│   ├── ecc.js         # ECC key generation and operations
│   ├── encryption.js   # AES-GCM encryption/decryption
│   ├── fileEncryption.js # File encryption utilities
│   ├── keyExchange.js  # ECDH key exchange protocol
│   └── keyStorage.js   # Secure key storage in IndexedDB
├── hooks/              # React custom hooks
│   ├── useAuth.js     # Authentication state management
│   └── useMessaging.js # Messaging functionality
├── services/           # API integration
│   └── api.js         # HTTP client for backend communication
├── utils/              # Helper utilities
│   └── helpers.js     # Validation, formatting, security helpers
├── App.jsx            # Main application component
└── main.jsx           # React application entry point
```

## 🌐 Backend API Integration

The frontend expects the following REST API endpoints from the backend:

### Authentication Endpoints
```
POST /api/auth/register
Body: { email, username, password, publicKey }
Response: { token, user }

POST /api/auth/login  
Body: { email, password }
Response: { token, user, contacts }

POST /api/auth/logout
Headers: { Authorization: "Bearer <token>" }
Response: { success }
```

### User Management
```
GET /api/users/profile
Headers: { Authorization: "Bearer <token>" }
Response: { user }

GET /api/users/contacts
Headers: { Authorization: "Bearer <token>" }
Response: { contacts }

POST /api/users/add-contact
Body: { username }
Response: { contact }
```

### Key Exchange
```
POST /api/keyexchange/initiate
Body: { targetUserId, ephemeralPublicKey, signature }
Response: { exchangeId }

POST /api/keyexchange/respond
Body: { exchangeId, ephemeralPublicKey, signature }
Response: { confirmed }
```

### Messaging
```
GET /api/messages/:contactId
Headers: { Authorization: "Bearer <token>" }
Response: { messages }

POST /api/messages/send
Body: { receiverId, encryptedMessage }
Response: { messageId }
```

### File Sharing
```
POST /api/files/upload
Body: FormData with encrypted file
Headers: { Authorization: "Bearer <token>" }
Response: { fileId, downloadUrl }

GET /api/files/:fileId
Headers: { Authorization: "Bearer <token>" }
Response: Encrypted file data
```

## 🔒 Security Implementation

- Each message includes: `senderId`, `receiverId`, `ciphertext`, `iv`, `authTag`, `timestamp`, `nonce`, `signature`
- Fresh random IV and nonce for each message
- Private keys never leave the client
- Session keys stored only in memory
- Timestamp validation (5-minute window)

## 🧪 Testing

```bash
# Run linting
npm run lint

# Build for production
npm run build

# Preview production build
npm run preview
```
