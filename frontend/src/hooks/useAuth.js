/**
 * Custom React hooks for authentication and user management
 * Handles login, registration, and key generation workflow
 */

import { useState, useEffect, useCallback } from 'react';
import { apiService } from '../services/api.js';
import { generateECCKeyPair, exportPublicKey, arrayBufferToBase64 } from '../crypto/ecc.js';
import { generateSigningKeyPair } from '../crypto/keyExchange.js';
import { storePrivateKey, retrievePrivateKey, storePublicKey, retrievePublicKey, deleteUserKeys } from '../crypto/keyStorage.js';

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
   * Register a new user with key generation
   * @param {Object} userData - User registration data
   * @returns {Promise<boolean>} - Success status
   */
  const register = useCallback(async (userData) => {
    try {
      setIsLoading(true);
      setError(null);

      const { email, username, password } = userData;

      // Generate ECC key pair for ECDH
      const eccKeyPair = await generateECCKeyPair();
      
      // Generate signing key pair for message authentication
      const signingKeyPair = await generateSigningKeyPair();

      // Export public keys for backend storage
      const eccPublicKeyData = await exportPublicKey(eccKeyPair.publicKey);
      const signingPublicKeyData = await exportPublicKey(signingKeyPair.publicKey);

      // Combine public keys for backend
      const publicKeyBundle = {
        ecc: arrayBufferToBase64(eccPublicKeyData),
        signing: arrayBufferToBase64(signingPublicKeyData),
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
        // Store private keys locally after successful registration
        await Promise.all([
          storePrivateKey(`${response.user.id}_ecc`, eccKeyPair.privateKey, password),
          storePrivateKey(`${response.user.id}_signing`, signingKeyPair.privateKey, password),
          storePublicKey(`${response.user.id}_ecc`, eccKeyPair.publicKey),
          storePublicKey(`${response.user.id}_signing`, signingKeyPair.publicKey)
        ]);

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
   * @param {string} email - User email
   * @param {string} password - User password
   * @returns {Promise<Object>} - Login response (requires OTP verification)
   */
  const login = useCallback(async (email, password) => {
    try {
      setIsLoading(true);
      setError(null);

      console.log('Starting login process...');
      const response = await apiService.login(email, password);

      // Check if OTP was sent successfully
      if (response.message && response.message.includes('OTP sent')) {
        return { success: true, requiresOtp: true, identifier: email };
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

        // Verify that user's private keys can be retrieved
        const eccPrivateKey = await retrievePrivateKey(`${response.user.id}_ecc`, password);
        const signingPrivateKey = await retrievePrivateKey(`${response.user.id}_signing`, password);

        if (!eccPrivateKey || !signingPrivateKey) {
          throw new Error('Unable to decrypt your private keys. Please check your password.');
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
      
      // Clear keys from local storage
      if (user) {
        await deleteUserKeys(user.id);
      }
      
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
  }, [user]);

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
    eccPrivate: null,
    signingPrivate: null,
    eccPublic: null,
    signingPublic: null
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  /**
   * Load user's private keys from storage
   * @param {string} userId - User ID
   * @param {string} password - User password for decryption
   * @returns {Promise<boolean>} - Success status
   */
  const loadKeys = useCallback(async (userId, password) => {
    console.log('loadKeys called with:', { userId, hasPassword: !!password });
    try {
      setIsLoading(true);
      setError(null);

      console.log('Attempting to retrieve keys...');
      const [eccPrivateKey, signingPrivateKey, eccPublicKey, signingPublicKey] = await Promise.all([
        retrievePrivateKey(`${userId}_ecc`, password),
        retrievePrivateKey(`${userId}_signing`, password),
        retrievePublicKey(`${userId}_ecc`),
        retrievePublicKey(`${userId}_signing`)
      ]);

      console.log('Retrieved keys:', {
        hasEccPrivate: !!eccPrivateKey,
        hasSigningPrivate: !!signingPrivateKey,
        hasEccPublic: !!eccPublicKey,
        hasSigningPublic: !!signingPublicKey
      });

      if (!eccPrivateKey || !signingPrivateKey) {
        throw new Error('Failed to load private keys');
      }

      const newKeys = {
        eccPrivate: eccPrivateKey,
        signingPrivate: signingPrivateKey,
        eccPublic: eccPublicKey,
        signingPublic: signingPublicKey
      };

      console.log('Setting keys:', newKeys);
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
   * @param {string} userId - User ID
   * @param {string} password - User password
   * @returns {Promise<boolean>} - Success status
   */
  const regenerateKeys = useCallback(async (userId, password) => {
    try {
      setIsLoading(true);
      setError(null);

      // Generate new key pairs
      const eccKeyPair = await generateECCKeyPair();
      const signingKeyPair = await generateSigningKeyPair();

      // Export new public keys for backend update
      const eccPublicKeyData = await exportPublicKey(eccKeyPair.publicKey);
      const signingPublicKeyData = await exportPublicKey(signingKeyPair.publicKey);

      const publicKeyBundle = {
        ecc: arrayBufferToBase64(eccPublicKeyData),
        signing: arrayBufferToBase64(signingPublicKeyData),
        timestamp: Date.now()
      };

      // Update backend with new public keys
      await apiService.updatePublicKey(JSON.stringify(publicKeyBundle));

      // Store new private keys locally
      await Promise.all([
        storePrivateKey(`${userId}_ecc`, eccKeyPair.privateKey, password),
        storePrivateKey(`${userId}_signing`, signingKeyPair.privateKey, password),
        storePublicKey(`${userId}_ecc`, eccKeyPair.publicKey),
        storePublicKey(`${userId}_signing`, signingKeyPair.publicKey)
      ]);

      // Update state
      setKeys({
        eccPrivate: eccKeyPair.privateKey,
        signingPrivate: signingKeyPair.privateKey,
        eccPublic: eccKeyPair.publicKey,
        signingPublic: signingKeyPair.publicKey
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
      eccPrivate: null,
      signingPrivate: null,
      eccPublic: null,
      signingPublic: null
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
        return JSON.parse(publicKeyData);
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