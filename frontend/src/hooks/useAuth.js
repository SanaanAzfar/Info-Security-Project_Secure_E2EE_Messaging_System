/**
 * Custom React hooks for authentication and user management
 * Handles login, registration, and key generation workflow
 * Uses RSA 2048-bit keys as required by project specifications
 */

import { useState, useEffect, useCallback } from 'react';
import { apiService } from '../services/api.js';
import { keyManager } from '../crypto/keyManagementIntegration.js';
import { arrayBufferToBase64, base64ToArrayBuffer } from '../crypto/encryption.js';

/**
 * Authentication hook for login, registration, and logout
 */
export function useAuth() {
  const [user, setUser] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [contacts, setContacts] = useState([]);

  // Check authentication status on mount
  useEffect(() => {
    checkAuthStatus();
  }, []);

  /**
   * Check if user is currently authenticated
   */
  const checkAuthStatus = useCallback(async () => {
    try {
      setIsLoading(true);
      const userInfo = await apiService.verifyToken();
      setUser(userInfo);
      setIsAuthenticated(true);
    } catch (error) {
      setUser(null);
      setIsAuthenticated(false);
    } finally {
      setIsLoading(false);
    }
  }, []);

  /**
   * Register a new user with RSA 2048-bit key generation
   * @param {Object} userData - User registration data
   * @returns {Promise<boolean>} - Success status
   */
  const register = useCallback(async (userData) => {
    try {
      setIsLoading(true);
      setError(null);

      const { email, username, password } = userData;

      // Generate RSA 2048-bit key pair for encryption as required by project
      const { publicKey, privateKey } = await keyManager.generateAndStoreKeys(`${email}_rsa`, password);

      // Export public key for backend storage
      const exportedPublicKey = await window.crypto.subtle.exportKey('jwk', publicKey);
      const publicKeyBundle = {
        rsa: JSON.stringify(exportedPublicKey),
        timestamp: Date.now()
      };

      // Register with backend
      const response = await apiService.register(
        email,
        username,
        password,
        JSON.stringify(publicKeyBundle)
      );

      if (response.success) {
        // Store user information for later retrieval
        localStorage.setItem('currentUser', JSON.stringify({
          id: response.user.id,
          email: email
        }));

        return true;
      }

      return false;
    } catch (error) {
      console.error('Registration error:', error);
      setError(error.message || 'Registration failed');
      return false;
    } finally {
      setIsLoading(false);
    }
  }, []);

  /**
   * Login user (first step - request OTP)
   * @param {string} identifier - Email or username
   * @param {string} password - User password
   * @returns {Promise<Object>} - Login response (requires OTP verification)
   */
  const login = useCallback(async (identifier, password) => {
    try {
      setIsLoading(true);
      setError(null);

      console.log('Starting login process...');
      const response = await apiService.login(identifier, password);

      // Check if OTP was sent successfully
      if (response.message && response.message.includes('OTP sent')) {
        return { success: true, requiresOtp: true, identifier: identifier };
      }

      // If login failed or unexpected response
      setError('Invalid email or password');
      return { success: false };
    } catch (error) {
      console.error('Login error:', error);
      setError(error.message || 'Login failed');
      return { success: false };
    } finally {
      setIsLoading(false);
    }
  }, []);

  /**
   * Verify OTP and complete login
   * @param {string} identifier - Email/username used for login
   * @param {string} otp - OTP code
   * @param {string} password - User password for key decryption
   * @returns {Promise<Object>} - Verification response
   */
  const verifyOtp = useCallback(async (identifier, otp, password) => {
    try {
      setIsLoading(true);
      setError(null);

      console.log('Verifying OTP...');
      const response = await apiService.verifyOtp(identifier, otp);

      if (response.success && response.user) {
        console.log('OTP verification successful, checking keys...');

        // Use the user's email from the response to retrieve keys (keys stored with email identifier)
        const userIdForKeys = response.user.email;

        // Verify that user's private keys can be retrieved
        const rsaPrivateKey = await keyManager.retrievePrivateKey(`${userIdForKeys}_rsa`, password);

        if (!rsaPrivateKey) {
          throw new Error('Unable to retrieve your private keys. Please contact support.');
        }

        console.log('Keys verified successfully');
        setUser(response.user);
        setContacts(response.contacts || []);
        setIsAuthenticated(true);

        // Return user data for key loading in App component
        return { success: true, user: response.user };
      }

      setError('Invalid OTP');
      return { success: false };
    } catch (error) {
      console.error('OTP verification error:', error);
      setError(error.message || 'OTP verification failed');
      return { success: false };
    } finally {
      setIsLoading(false);
    }
  }, []);

  /**
   * Logout user and clear local keys
   */
  const logout = useCallback(async () => {
    try {
      setIsLoading(true);

      // Clear user information from local storage
      localStorage.removeItem('currentUser');

      // Logout from backend
      await apiService.logout();

      setUser(null);
      setContacts([]);
      setIsAuthenticated(false);
    } catch (error) {
      console.error('Logout error:', error);
      setError(error.message || 'Logout failed');
    } finally {
      setIsLoading(false);
    }
  }, []);

  /**
   * Add a new contact
   * @param {Object} contact - Contact data
   */
  const addContact = useCallback((contact) => {
    setContacts(prev => [...prev, contact]);
  }, []);

  /**
   * Fetch user's contacts from backend
   * @returns {Promise<Array>} - Array of contacts
   */
  const fetchContacts = useCallback(async () => {
    try {
      const response = await apiService.getContacts();
      setContacts(response.contacts || []);
      return response.contacts || [];
    } catch (error) {
      console.error('Failed to fetch contacts:', error);
      setError(error.message || 'Failed to fetch contacts');
      return [];
    }
  }, []);

  /**
   * Fetch user profile from backend
   * @returns {Promise<Object>} - User profile data
   */
  const fetchUserProfile = useCallback(async () => {
    try {
      const response = await apiService.getUserProfile();
      setUser(response.user);
      return response.user;
    } catch (error) {
      console.error('Failed to fetch user profile:', error);
      setError(error.message || 'Failed to fetch user profile');
      return null;
    }
  }, []);

  /**
   * Clear error state
   */
  const clearError = useCallback(() => {
    setError(null);
  }, []);

  return {
    user,
    isAuthenticated,
    isLoading,
    error,
    contacts,
    register,
    login,
    verifyOtp,
    logout,
    addContact,
    fetchContacts,
    fetchUserProfile,
    clearError,
    checkAuthStatus
  };
}

/**
 * Hook for managing user keys and key operations
 */
export function useKeys() {
  const [keys, setKeys] = useState({
    rsaPrivate: null,
    rsaPublic: null
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  /**
   * Load user's private keys from storage
   * @param {string} userId - User ID (email)
   * @param {string} password - User password for key decryption
   * @returns {Promise<boolean>} - Success status
   */
  const loadKeys = useCallback(async (userId, password) => {
    console.log('loadKeys called with:', { userId });
    try {
      setIsLoading(true);
      setError(null);

      console.log('Attempting to retrieve RSA keys...');
      const { publicKey, privateKey } = await keyManager.retrieveKeys(`${userId}_rsa`, password);

      console.log('Retrieved RSA keys:', {
        hasRsaPrivate: !!privateKey,
        hasRsaPublic: !!publicKey
      });

      if (!privateKey) {
        throw new Error('Failed to load private keys');
      }

      const newKeys = {
        rsaPrivate: privateKey,
        rsaPublic: publicKey
      };

      console.log('Setting RSA keys:', newKeys);
      setKeys(newKeys);

      return true;
    } catch (error) {
      console.error('Key loading error:', error);
      setError(error.message || 'Failed to load keys');
      return false;
    } finally {
      setIsLoading(false);
    }
  }, []);

  /**
   * Generate new key pairs (for key rotation)
   * @param {string} userId - User ID (email)
   * @param {string} password - User password for key encryption
   * @returns {Promise<boolean>} - Success status
   */
  const regenerateKeys = useCallback(async (userId, password) => {
    try {
      setIsLoading(true);
      setError(null);

      // Generate new RSA 2048-bit key pairs
      const { publicKey, privateKey } = await keyManager.generateAndStoreKeys(`${userId}_rsa`, password);

      // Export new public key for backend update
      const exportedPublicKey = await window.crypto.subtle.exportKey('jwk', publicKey);
      const publicKeyBundle = {
        rsa: JSON.stringify(exportedPublicKey),
        timestamp: Date.now()
      };

      // Update backend with new public key
      await apiService.updatePublicKey(JSON.stringify(publicKeyBundle));

      // Update state
      setKeys({
        rsaPrivate: privateKey,
        rsaPublic: publicKey
      });

      return true;
    } catch (error) {
      console.error('Key regeneration error:', error);
      setError(error.message || 'Failed to regenerate keys');
      return false;
    } finally {
      setIsLoading(false);
    }
  }, []);

  /**
   * Clear keys from state (on logout)
   */
  const clearKeys = useCallback(() => {
    setKeys({
      rsaPrivate: null,
      rsaPublic: null
    });
  }, []);

  /**
   * Get public key for another user from backend
   * @param {string} userId - Other user's ID
   * @returns {Promise<Object|null>} - Public key bundle or null
   */
  const getUserPublicKey = useCallback(async (userId) => {
    try {
      const publicKeyData = await apiService.getUserPublicKey(userId);
      if (publicKeyData) {
        const parsedData = JSON.parse(publicKeyData);

        // Import the RSA public key
        if (parsedData.rsa) {
          const publicKeyJWK = JSON.parse(parsedData.rsa);
          const publicKey = await window.crypto.subtle.importKey(
            'jwk',
            publicKeyJWK,
            {
              name: 'RSA-OAEP',
              hash: 'SHA-256'
            },
            true,
            ['encrypt']
          );

          return { rsa: publicKey };
        }
      }
      return null;
    } catch (error) {
      console.error('Failed to get user public key:', error);
      return null;
    }
  }, []);

  /**
   * Clear error state
   */
  const clearError = useCallback(() => {
    setError(null);
  }, []);

  return {
    keys,
    isLoading,
    error,
    loadKeys,
    regenerateKeys,
    clearKeys,
    getUserPublicKey,
    clearError
  };
}