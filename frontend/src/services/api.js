/**
 * API service for backend communication
 * Handles REST API calls and Socket.IO connections for real-time messaging
 * Includes authentication token management and error handling
 */

import { io } from 'socket.io-client';

// API Configuration from environment variables
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3000/api';
const WS_BASE_URL = import.meta.env.VITE_WS_URL || 'http://localhost:3000';

class ApiService {
  constructor() {
    this.authToken = null;
    this.socket = null;
    this.messageHandlers = new Map();
    this.connectionListeners = new Set();
    this.loadAuthToken();
  }

  /**
   * Set authentication token and store it securely
   * @param {string} token - JWT or session token from backend
   */
  setAuthToken(token) {
    this.authToken = token;
    if (token) {
      sessionStorage.setItem('authToken', token);
    } else {
      sessionStorage.removeItem('authToken');
    }
  }

  /**
   * Load authentication token from storage
   */
  loadAuthToken() {
    this.authToken = sessionStorage.getItem('authToken');
  }

  /**
   * Get authorization headers for API requests
   * @returns {Object} - Headers object with authorization
   */
  getAuthHeaders() {
    const headers = {
      'Content-Type': 'application/json',
    };
    
    if (this.authToken) {
      headers.Authorization = `Bearer ${this.authToken}`;
    }
    
    return headers;
  }

  /**
   * Make authenticated API request
   * @param {string} endpoint - API endpoint (without base URL)
   * @param {Object} options - Fetch options
   * @returns {Promise<Object>} - Response data
   */
  async apiRequest(endpoint, options = {}) {
    const url = `${API_BASE_URL}${endpoint}`;
    
    const requestOptions = {
      ...options,
      headers: {
        ...this.getAuthHeaders(),
        ...options.headers,
      },
    };

    try {
      const response = await fetch(url, requestOptions);
      
      if (!response.ok) {
        if (response.status === 401) {
          this.setAuthToken(null);
          throw new Error('Authentication required');
        }
        throw new Error(`API request failed: ${response.status} ${response.statusText}`);
      }

      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        return await response.json();
      }
      
      return await response.text();
    } catch (error) {
      console.error('API request error:', error);
      throw error;
    }
  }

  // Authentication API calls

  /**
   * Register a new user
   * @param {string} email - User email
   * @param {string} username - Username
   * @param {string} password - Password
   * @param {string} publicKey - Base64 encoded public key
   * @returns {Promise<Object>} - Registration response
   */
  async register(email, username, password, publicKey) {
    return this.apiRequest('/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        email,
        username,
        password,
        publicKey, // Only public key is sent to server
      }),
    });
  }

  /**
   * Login user
   * @param {string} email - User email
   * @param {string} password - Password
   * @returns {Promise<Object>} - Login response with token
   */
  async login(email, password) {
    const response = await this.apiRequest('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    
    if (response.token) {
      this.setAuthToken(response.token);
    }
    
    return response;
  }

  /**
   * Logout user
   * @returns {Promise<void>}
   */
  async logout() {
    try {
      await this.apiRequest('/auth/logout', {
        method: 'POST',
      });
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      this.setAuthToken(null);
      this.disconnectWebSocket();
    }
  }

  /**
   * Verify current token validity
   * @returns {Promise<Object>} - User info if token is valid
   */
  async verifyToken() {
    return this.apiRequest('/auth/verify');
  }

  // User management API calls

  /**
   * Get user profile
   * @returns {Promise<Object>} - User profile data
   */
  async getUserProfile() {
    return this.apiRequest('/user/profile');
  }

  /**
   * Get user's public key
   * @param {string} userId - User ID to get public key for
   * @returns {Promise<string>} - Base64 encoded public key
   */
  async getUserPublicKey(userId) {
    const response = await this.apiRequest(`/user/${userId}/publickey`);
    return response.publicKey;
  }

  /**
   * Update user's public key
   * @param {string} publicKey - New public key (base64 encoded)
   * @returns {Promise<Object>} - Update response
   */
  async updatePublicKey(publicKey) {
    return this.apiRequest('/user/publickey', {
      method: 'PUT',
      body: JSON.stringify({ publicKey }),
    });
  }

  /**
   * Search for users (for contact list)
   * @param {string} query - Search query (username or email)
   * @returns {Promise<Array>} - Array of user objects
   */
  async searchUsers(query) {
    return this.apiRequest(`/user/search?q=${encodeURIComponent(query)}`);
  }

  /**
   * Add a contact by username or email
   * @param {string} identifier - Username or email to add as contact
   * @param {string} type - Type of identifier ('username' or 'email')
   * @returns {Promise<Object>} - Contact response
   */
  async addContact(identifier, type = 'username') {
    const payload = type === 'email' 
      ? { email: identifier }
      : { username: identifier };
      
    return this.apiRequest('/users/add-contact', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  // Messaging API calls

  /**
   * Send a message to another user
   * @param {Object} encryptedMessage - Encrypted message object
   * @returns {Promise<Object>} - Send response
   */
  async sendMessage(encryptedMessage) {
    return this.apiRequest('/messages/send', {
      method: 'POST',
      body: JSON.stringify(encryptedMessage),
    });
  }

  /**
   * Get message history with a user
   * @param {string} userId - Other user's ID
   * @param {number} limit - Number of messages to retrieve
   * @param {number} offset - Offset for pagination
   * @returns {Promise<Array>} - Array of message objects
   */
  async getMessages(userId, limit = 50, offset = 0) {
    return this.apiRequest(`/messages/${userId}?limit=${limit}&offset=${offset}`);
  }

  /**
   * Mark messages as read
   * @param {Array<string>} messageIds - Array of message IDs
   * @returns {Promise<Object>} - Update response
   */
  async markMessagesRead(messageIds) {
    return this.apiRequest('/messages/read', {
      method: 'PUT',
      body: JSON.stringify({ messageIds }),
    });
  }

  // Key Exchange API calls

  /**
   * Initiate key exchange with another user
   * @param {Object} keyExchangeData - Key exchange initiation data
   * @returns {Promise<Object>} - Key exchange response
   */
  async initiateKeyExchange(keyExchangeData) {
    return this.apiRequest('/keyexchange/initiate', {
      method: 'POST',
      body: JSON.stringify({
        targetUserId: keyExchangeData.receiverId,
        ephemeralPublicKey: keyExchangeData.ephemeralPublicKey,
        signature: keyExchangeData.signature,
        timestamp: keyExchangeData.timestamp,
        nonce: keyExchangeData.nonce
      }),
    });
  }

  /**
   * Respond to key exchange request
   * @param {Object} responseData - Key exchange response data
   * @returns {Promise<Object>} - Response confirmation
   */
  async respondToKeyExchange(responseData) {
    return this.apiRequest('/keyexchange/respond', {
      method: 'POST',
      body: JSON.stringify({
        exchangeId: responseData.exchangeId,
        ephemeralPublicKey: responseData.ephemeralPublicKey,
        signature: responseData.signature,
        timestamp: responseData.timestamp,
        nonce: responseData.nonce
      }),
    });
  }

  // File sharing API calls

  /**
   * Upload encrypted file chunks
   * @param {string} fileId - File identifier
   * @param {Array} chunks - Encrypted file chunks
   * @param {Object} metadata - File metadata
   * @returns {Promise<Object>} - Upload response
   */
  async uploadFile(fileId, chunks, metadata) {
    return this.apiRequest('/files/upload', {
      method: 'POST',
      body: JSON.stringify({
        fileId,
        chunks,
        metadata,
      }),
    });
  }

  /**
   * Download encrypted file
   * @param {string} fileId - File identifier
   * @returns {Promise<Object>} - File data and metadata
   */
  async downloadFile(fileId) {
    return this.apiRequest(`/files/${fileId}`);
  }

  /**
   * Share file with another user
   * @param {string} fileId - File identifier
   * @param {string} userId - User to share with
   * @param {Object} encryptedMetadata - Encrypted file metadata
   * @returns {Promise<Object>} - Share response
   */
  async shareFile(fileId, userId, encryptedMetadata) {
    return this.apiRequest('/files/share', {
      method: 'POST',
      body: JSON.stringify({
        fileId,
        userId,
        encryptedMetadata,
      }),
    });
  }

  // WebSocket connection for real-time messaging

  /**
   * Connect to Socket.IO for real-time messaging
   * @returns {Promise<void>}
   */
  async connectWebSocket() {
    if (this.socket && this.socket.connected) {
      return;
    }

    return new Promise((resolve, reject) => {
      try {
        console.log('Connecting to Socket.IO...', { 
          url: WS_BASE_URL, 
          hasToken: !!this.authToken 
        });

        // Create Socket.IO connection
        this.socket = io(WS_BASE_URL, {
          auth: {
            token: this.authToken
          },
          autoConnect: false
        });

        this.socket.on('connect', () => {
          console.log('Socket.IO connected successfully');
          
          // Authenticate the socket connection
          this.socket.emit('authenticate', { token: this.authToken });
          
          this.notifyConnectionListeners('connected');
          resolve();
        });

        this.socket.on('disconnect', () => {
          console.log('Socket.IO disconnected');
          this.notifyConnectionListeners('disconnected');
        });

        this.socket.on('connect_error', (error) => {
          console.error('Socket.IO connection error:', error);
          this.notifyConnectionListeners('error', error);
          reject(error);
        });

        // Set up message handlers
        this.socket.on('message_received', (message) => {
          this.handleWebSocketMessage({ type: 'message', data: message });
        });

        this.socket.on('key_exchange_request', (data) => {
          this.handleWebSocketMessage({ type: 'key_exchange_initiate', data });
        });

        this.socket.on('key_exchange_response', (data) => {
          this.handleWebSocketMessage({ type: 'key_exchange_response', data });
        });

        this.socket.on('key_exchange_confirmation', (data) => {
          this.handleWebSocketMessage({ type: 'key_exchange_confirmation', data });
        });

        this.socket.on('user_online', (data) => {
          this.handleWebSocketMessage({ type: 'user_online', data });
        });

        this.socket.on('user_offline', (data) => {
          this.handleWebSocketMessage({ type: 'user_offline', data });
        });

        this.socket.on('typing_indicator', (data) => {
          this.handleWebSocketMessage({ type: 'typing_indicator', data });
        });

        // Connect the socket
        console.log('Starting Socket.IO connection...');
        this.socket.connect();
      } catch (error) {
        console.error('Failed to create Socket.IO connection:', error);
        reject(error);
      }
    });
  }

  /**
   * Disconnect Socket.IO
   */
  disconnectWebSocket() {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
  }

  /**
   * Send message through Socket.IO
   * @param {string} event - Event name
   * @param {Object} data - Data to send
   */
  sendWebSocketMessage(event, data) {
    if (this.socket && this.socket.connected) {
      this.socket.emit(event, data);
    } else {
      throw new Error('Socket.IO not connected');
    }
  }

  /**
   * Check if Socket.IO is connected
   * @returns {boolean} - Connection status
   */
  isConnected() {
    return this.socket && this.socket.connected;
  }

  /**
   * Handle incoming WebSocket messages
   * @param {Object} message - Received message
   */
  handleWebSocketMessage(message) {
    const handler = this.messageHandlers.get(message.type);
    if (handler) {
      handler(message);
    } else {
      console.log('Unhandled WebSocket message:', message);
    }
  }

  /**
   * Register message handler for specific message types
   * @param {string} type - Message type
   * @param {Function} handler - Handler function
   */
  onWebSocketMessage(type, handler) {
    this.messageHandlers.set(type, handler);
  }

  /**
   * Add connection state listener
   * @param {Function} listener - Listener function
   */
  onConnectionStateChange(listener) {
    this.connectionListeners.add(listener);
  }

  /**
   * Remove connection state listener
   * @param {Function} listener - Listener function
   */
  offConnectionStateChange(listener) {
    this.connectionListeners.delete(listener);
  }

  /**
   * Notify connection state listeners
   * @param {string} state - Connection state
   * @param {*} data - Additional data
   */
  notifyConnectionListeners(state, data) {
    for (const listener of this.connectionListeners) {
      try {
        listener(state, data);
      } catch (error) {
        console.error('Connection listener error:', error);
      }
    }
  }
}

// Export singleton instance
export const apiService = new ApiService();