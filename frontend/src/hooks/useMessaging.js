/**
 * React hook for secure messaging functionality
 * Handles message encryption, decryption, and real-time communication
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { apiService } from '../services/api.js';
import { sessionManager, initiateKeyExchange, respondToKeyExchange, completeKeyExchange } from '../crypto/keyExchange.js';
import { createEncryptedMessage, decryptReceivedMessage } from '../crypto/encryption.js';
import { base64ToArrayBuffer } from '../crypto/ecc.js';

/**
 * Hook for managing secure messaging
 */
export function useMessaging(user, keys) {
  console.log('useMessaging hook called with:', { 
    hasUser: !!user, 
    userId: user?.id,
    hasKeys: !!keys,
    hasEccPrivate: !!keys?.eccPrivate 
  });
  
  const [conversations, setConversations] = useState(new Map());
  const [activeConversation, setActiveConversation] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  
  // Message sequence tracking
  const sequenceNumbers = useRef(new Map()); // Map<userId, number>
  const usedNonces = useRef(new Map()); // Map<userId, Set<string>>
  const pendingExchanges = useRef(new Map()); // Map<exchangeId, { userId, ephemeralPrivateKey }>
  const cachedSigningKeys = useRef(new Map()); // Map<userId, CryptoKey>
  const pendingSessions = useRef(new Map()); // Map<userId, number> (last attempt timestamp)
  const pendingMessages = useRef(new Map()); // Map<userId, Array<{ content: string }>>
  const receivedMessageIds = useRef(new Set()); // Track processed message IDs

  const getRemoteSigningKey = useCallback(async (otherUserId) => {
    if (cachedSigningKeys.current.has(otherUserId)) {
      return cachedSigningKeys.current.get(otherUserId);
    }

    const publicKeyPayload = await apiService.getUserPublicKey(otherUserId);
    if (!publicKeyPayload) {
      throw new Error('Remote public key not available');
    }

    let keyBundle;
    try {
      keyBundle = typeof publicKeyPayload === 'string'
        ? JSON.parse(publicKeyPayload)
        : publicKeyPayload;
    } catch (error) {
      console.error('Invalid remote public key bundle:', error);
      throw new Error('Invalid public key bundle received');
    }

    if (!keyBundle.signing) {
      throw new Error('Remote signing key missing');
    }

    const signingKeyData = base64ToArrayBuffer(keyBundle.signing);
    const signingKey = await window.crypto.subtle.importKey(
      'raw',
      signingKeyData,
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['verify']
    );

    cachedSigningKeys.current.set(otherUserId, signingKey);
    return signingKey;
  }, []);

  /**
   * Add message to conversation state
   */
  const addMessageToConversation = useCallback((userId, message) => {
    setConversations(prev => {
      const newConversations = new Map(prev);
      const conversation = newConversations.get(userId) || {
        userId,
        messages: [],
        lastActivity: Date.now(),
        unreadCount: 0
      };

      conversation.messages.push(message);
      conversation.lastActivity = Date.now();
      
      // Increment unread count if not in active conversation
      if (activeConversation !== userId && message.senderId !== user?.id) {
        conversation.unreadCount += 1;
      }

      newConversations.set(userId, conversation);
      return newConversations;
    });
  }, [activeConversation, user]);

  const currentUserId = user?.id;
  const signingPrivateKey = keys?.signingPrivate;
  const eccPrivateKey = keys?.eccPrivate;

  const queueMessageForUser = useCallback((targetUserId, content) => {
    if (!pendingMessages.current.has(targetUserId)) {
      pendingMessages.current.set(targetUserId, []);
    }
    pendingMessages.current.get(targetUserId).push({ content });
  }, []);

  const sendEncryptedMessage = useCallback(async (targetUserId, plaintext) => {
    if (!currentUserId) {
      throw new Error('User not available for sending messages');
    }

    const session = sessionManager.getSession(targetUserId);
    if (!session) {
      throw new Error('Session not available for encryption');
    }

    const currentSeq = sequenceNumbers.current.get(targetUserId) || 0;
    const nextSeq = currentSeq + 1;

    const encryptedMessage = await createEncryptedMessage(
      plaintext,
      currentUserId,
      targetUserId,
      session.sessionKey,
      nextSeq
    );

    const response = await apiService.sendMessage(encryptedMessage);

    if (response.success) {
      sequenceNumbers.current.set(targetUserId, nextSeq);

      const messageObj = {
        id: response.messageId || `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        senderId: currentUserId,
        receiverId: targetUserId,
        content: plaintext,
        timestamp: Date.now(),
        type: 'text',
        isEncrypted: true,
        status: 'sent'
      };

      addMessageToConversation(targetUserId, messageObj);
      return messageObj;
    }

    throw new Error('Failed to send message');
  }, [currentUserId, addMessageToConversation]);

  const flushQueuedMessages = useCallback(async (targetUserId) => {
    const queue = pendingMessages.current.get(targetUserId);
    if (!queue || queue.length === 0) {
      return;
    }

    console.log(`Sending ${queue.length} queued message(s) to ${targetUserId}`);

    for (const queued of queue) {
      try {
        await sendEncryptedMessage(targetUserId, queued.content);
      } catch (err) {
        console.error('Failed to send queued message:', err);
        setError('Failed to send a queued message. Please retry.');
      }
    }

    pendingMessages.current.delete(targetUserId);
  }, [sendEncryptedMessage, setError]);

  const KEY_EXCHANGE_RETRY_DELAY = 5000;

  const ensureKeyExchange = useCallback(async (receiverId) => {
    if (!currentUserId || !signingPrivateKey) {
      throw new Error('User keys not ready for key exchange');
    }

    const now = Date.now();
    const lastAttempt = pendingSessions.current.get(receiverId) || 0;
    if (now - lastAttempt < KEY_EXCHANGE_RETRY_DELAY) {
      console.log('Key exchange attempt throttled for user:', receiverId);
      return;
    }

    pendingSessions.current.set(receiverId, now);

    try {
      console.log('No session found, initiating key exchange with:', receiverId);

      const { keyExchangeMessage, ephemeralPrivateKey } = await initiateKeyExchange(
        currentUserId,
        receiverId,
        signingPrivateKey
      );

      const initiationResponse = await apiService.initiateKeyExchange(keyExchangeMessage);

      if (initiationResponse?.exchangeId) {
        pendingExchanges.current.set(initiationResponse.exchangeId, {
          userId: receiverId,
          ephemeralPrivateKey
        });
      }
    } catch (error) {
      console.error('Failed to initiate key exchange:', error);
      pendingSessions.current.delete(receiverId);
      throw error;
    }
  }, [currentUserId, signingPrivateKey]);

  /**
   * Handle incoming encrypted messages
   */
  const handleIncomingMessage = useCallback((messageData) => {
    if (!user) return;

    const payload = messageData?.data || messageData;
    if (!payload) {
      console.warn('Incoming message payload missing:', messageData);
      return;
    }

    const { senderId } = payload;
    if (!senderId) {
      console.warn('Incoming message missing senderId:', payload);
      return;
    }

    // Ignore websocket echoes for messages we already rendered locally
    if (senderId === user.id) {
      console.debug('Ignoring self-originated message event');
      return;
    }
    const session = sessionManager.getSession(senderId);
    
    if (!session) {
      console.error('No session found for sender:', senderId);
      return;
    }

    const messageId = payload.id || `msg_${payload.timestamp}`;
    if (messageId && receivedMessageIds.current.has(messageId)) {
      console.debug('Duplicate message detected, skipping.', { messageId, senderId });
      return;
    }

    // Get expected sequence number
    const expectedSeq = sequenceNumbers.current.get(senderId) || 0;
    const incomingSeq = typeof payload.sequenceNumber === 'number'
      ? payload.sequenceNumber
      : null;
    let targetSeq = expectedSeq + 1;

    if (incomingSeq !== null) {
      if (incomingSeq < targetSeq) {
        console.warn('Stale or duplicate message detected. Ignoring.', {
          senderId,
          incomingSeq,
          expectedNext: targetSeq
        });
        return;
      }

      if (incomingSeq > targetSeq) {
        console.warn('Out-of-sync sequence detected. Adjusting expectation.', {
          senderId,
          incomingSeq,
          previousExpected: targetSeq
        });
        sequenceNumbers.current.set(senderId, incomingSeq - 1);
        targetSeq = incomingSeq;
      }
    }
    
    // Get used nonces set
    if (!usedNonces.current.has(senderId)) {
      usedNonces.current.set(senderId, new Set());
    }
    const nonces = usedNonces.current.get(senderId);

    const decryptionPayload = incomingSeq === null
      ? { ...payload, sequenceNumber: targetSeq }
      : payload;

    // Decrypt message
    decryptReceivedMessage(
      decryptionPayload,
      session.sessionKey,
      targetSeq,
      nonces
    ).then(result => {
      if (result.isValid) {
        // Update sequence number
        sequenceNumbers.current.set(senderId, targetSeq);

        // Add to conversation
        const message = {
          id: messageId,
          senderId,
          receiverId: user.id,
          content: result.message,
          timestamp: Date.now(),
          type: 'text',
          isEncrypted: true
        };

        if (messageId) {
          receivedMessageIds.current.add(messageId);
        }

        addMessageToConversation(senderId, message);
      } else {
        console.error('Message decryption failed:', result.error);
        setError(`Message decryption failed: ${result.error}`);
      }
    }).catch(error => {
      console.error('Message processing error:', error);
      setError('Failed to process incoming message');
    });
  }, [user, addMessageToConversation]);

  /**
   * Send encrypted message to another user
   */
  const sendMessage = useCallback(async (receiverId, message) => {
    if (!currentUserId || !eccPrivateKey) {
      throw new Error('User not authenticated or keys not loaded');
    }
    if (!receiverId) {
      throw new Error('No recipient specified');
    }

    try {
      setIsLoading(true);

      const session = sessionManager.getSession(receiverId);
      if (!session) {
        await ensureKeyExchange(receiverId);
        queueMessageForUser(receiverId, message);
        console.log('Message queued until key exchange completes');
        return {
          status: 'queued',
          message: 'Key exchange in progress. Message will be sent automatically.'
        };
      }

      return await sendEncryptedMessage(receiverId, message);
    } catch (error) {
      console.error('Send message error:', error);
      setError(error.message || 'Failed to send message');
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, [currentUserId, eccPrivateKey, ensureKeyExchange, queueMessageForUser, sendEncryptedMessage]);

  /**
   * Load conversation history with a user
   */
  const loadConversation = useCallback(async (userId) => {
    try {
      setIsLoading(true);

      // Get session for decryption
      const session = sessionManager.getSession(userId);
      if (!session) {
        // Try to load messages from backend (they'll be encrypted)
        const messages = await apiService.getMessages(userId);
        
        // Create conversation without decrypted content
        const conversation = {
          userId,
          messages: messages.map(msg => ({
            ...msg,
            content: '[Encrypted - Session not available]',
            isEncrypted: false
          })),
          lastActivity: Date.now(),
          unreadCount: 0
        };

        setConversations(prev => new Map(prev).set(userId, conversation));
        return;
      }

      // Get encrypted messages from backend
      const encryptedMessages = await apiService.getMessages(userId);
      const decryptedMessages = [];
      let highestSequence = sequenceNumbers.current.get(userId) || 0;

      // Get used nonces set
      if (!usedNonces.current.has(userId)) {
        usedNonces.current.set(userId, new Set());
      }
      const nonces = usedNonces.current.get(userId);

      // Decrypt messages
      for (const encMsg of encryptedMessages) {
        try {
          const result = await decryptReceivedMessage(
            encMsg,
            session.sessionKey,
            encMsg.sequenceNumber,
            nonces
          );

          if (result.isValid) {
            if (encMsg.id && receivedMessageIds.current.has(encMsg.id)) {
              continue;
            }
            decryptedMessages.push({
              id: encMsg.id,
              senderId: encMsg.senderId,
              receiverId: encMsg.receiverId,
              content: result.message,
              timestamp: encMsg.timestamp,
              type: 'text',
              isEncrypted: true
            });

            if (typeof encMsg.sequenceNumber === 'number') {
              highestSequence = Math.max(highestSequence, encMsg.sequenceNumber);
            }

            if (encMsg.id) {
              receivedMessageIds.current.add(encMsg.id);
            }
          }
        } catch (error) {
          console.error('Failed to decrypt message:', error);
          // Add placeholder for failed decryption
          decryptedMessages.push({
            id: encMsg.id,
            senderId: encMsg.senderId,
            receiverId: encMsg.receiverId,
            content: '[Failed to decrypt]',
            timestamp: encMsg.timestamp,
            type: 'text',
            isEncrypted: false
          });
        }
      }

      const conversation = {
        userId,
        messages: decryptedMessages,
        lastActivity: Date.now(),
        unreadCount: 0
      };

      setConversations(prev => new Map(prev).set(userId, conversation));

      if (decryptedMessages.length > 0 && highestSequence >= 0) {
        sequenceNumbers.current.set(userId, highestSequence);
      }
    } catch (error) {
      console.error('Load conversation error:', error);
      setError('Failed to load conversation');
    } finally {
      setIsLoading(false);
    }
  }, []);

  /**
   * Set active conversation and mark as read
   */
  const selectConversation = useCallback(async (userId) => {
    setActiveConversation(userId);

    // Mark messages as read
    const conversation = conversations.get(userId);
    if (conversation && conversation.unreadCount > 0) {
      const unreadMessages = conversation.messages
        .filter(msg => msg.senderId === userId)
        .slice(-conversation.unreadCount)
        .map(msg => msg.id);

      try {
        await apiService.markMessagesRead(unreadMessages);
        
        // Update local state
        setConversations(prev => {
          const newConversations = new Map(prev);
          const conv = { ...newConversations.get(userId) };
          conv.unreadCount = 0;
          newConversations.set(userId, conv);
          return newConversations;
        });
      } catch (error) {
        console.error('Failed to mark messages as read:', error);
      }
    }
  }, [conversations]);

  /**
   * Key exchange placeholder handlers
   */
  const initializeSessionState = useCallback((otherUserId) => {
    sequenceNumbers.current.set(otherUserId, 0);
    usedNonces.current.set(otherUserId, new Set());
  }, []);

  const handleKeyExchangeInitiate = useCallback(async (message) => {
    const payload = message?.data || message;
    if (!payload || !user || !signingPrivateKey) {
      return;
    }

    try {
      const senderSigningKey = await getRemoteSigningKey(payload.fromUserId);
      const { responseMessage, sessionKey } = await respondToKeyExchange(
        {
          senderId: payload.fromUserId,
          receiverId: user.id,
          ephemeralPublicKey: payload.ephemeralPublicKey,
          timestamp: payload.timestamp,
          nonce: payload.nonce,
          signature: payload.signature
        },
        signingPrivateKey,
        senderSigningKey
      );

      sessionManager.storeSession(payload.fromUserId, sessionKey);
      initializeSessionState(payload.fromUserId);
      pendingSessions.current.delete(payload.fromUserId);
      await flushQueuedMessages(payload.fromUserId);

      await apiService.respondToKeyExchange({
        exchangeId: payload.exchangeId,
        ephemeralPublicKey: responseMessage.ephemeralPublicKey,
        signature: responseMessage.signature,
        timestamp: responseMessage.timestamp,
        nonce: responseMessage.nonce
      });

      console.log('Key exchange response sent for user:', payload.fromUserId);
    } catch (exchangeError) {
      console.error('Failed to handle key exchange initiate:', exchangeError);
      setError('Failed to respond to key exchange. Please try again.');
    }
  }, [user, signingPrivateKey, getRemoteSigningKey, initializeSessionState, flushQueuedMessages]);

  const handleKeyExchangeResponse = useCallback(async (message) => {
    const payload = message?.data || message;
    if (!payload || !user) {
      return;
    }

    const pendingExchange = pendingExchanges.current.get(payload.exchangeId);
    if (!pendingExchange) {
      console.warn('No pending exchange found for response:', payload.exchangeId);
      return;
    }

    try {
      const receiverSigningKey = await getRemoteSigningKey(payload.fromUserId);
      const { sessionKey } = await completeKeyExchange(
        {
          senderId: payload.fromUserId,
          receiverId: user.id,
          ephemeralPublicKey: payload.ephemeralPublicKey,
          timestamp: payload.timestamp,
          nonce: payload.nonce,
          signature: payload.signature
        },
        pendingExchange.ephemeralPrivateKey,
        receiverSigningKey
      );

      sessionManager.storeSession(pendingExchange.userId, sessionKey);
      initializeSessionState(pendingExchange.userId);
      pendingExchanges.current.delete(payload.exchangeId);
      pendingSessions.current.delete(pendingExchange.userId);
      await flushQueuedMessages(pendingExchange.userId);

      console.log('Key exchange completed with user:', pendingExchange.userId);
    } catch (completionError) {
      console.error('Failed to complete key exchange:', completionError);
      pendingExchanges.current.delete(payload.exchangeId);
      setError('Key exchange completion failed. Please retry.');
    }
  }, [user, getRemoteSigningKey, initializeSessionState, flushQueuedMessages]);

  const handleKeyExchangeConfirmation = useCallback((message) => {
    const payload = message?.data || message;
    console.log('Key exchange confirmation received:', payload);
  }, []);

  /**
   * Connect to WebSocket for real-time messaging
   */
  const connectToWebSocket = useCallback(async () => {
    console.log('connectToWebSocket called');
    
    try {
      // Set up connection state listener first
      apiService.onConnectionStateChange((state) => {
        console.log('Connection state changed:', state);
        setIsConnected(state === 'connected');
        if (state === 'error') {
          setError('Connection to messaging service failed');
        }
      });

      console.log('About to call apiService.connectWebSocket()');
      // Connect to WebSocket
      await apiService.connectWebSocket();
      console.log('apiService.connectWebSocket() completed');

      // Set up message handlers
      apiService.onWebSocketMessage('message', handleIncomingMessage);
      apiService.onWebSocketMessage('key_exchange_initiate', handleKeyExchangeInitiate);
      apiService.onWebSocketMessage('key_exchange_response', handleKeyExchangeResponse);
      apiService.onWebSocketMessage('key_exchange_confirmation', handleKeyExchangeConfirmation);

      console.log('WebSocket connection setup completed');
    } catch (error) {
      console.error('WebSocket connection failed:', error);
      setError('Failed to connect to messaging service');
      setIsConnected(false);
    }
  }, [handleIncomingMessage, handleKeyExchangeInitiate, handleKeyExchangeResponse, handleKeyExchangeConfirmation]);

  /**
   * Disconnect from WebSocket
   */
  const disconnectFromWebSocket = useCallback(() => {
    apiService.disconnectWebSocket();
    setIsConnected(false);
  }, []);

  useEffect(() => {
    if (user && keys.eccPrivate) {
      console.log('User and keys available, connecting to WebSocket...', {
        userId: user.id,
        hasPrivateKey: !!keys.eccPrivate
      });
      connectToWebSocket();
    } else {
      console.log('User or keys not available:', {
        hasUser: !!user,
        hasKeys: !!keys.eccPrivate
      });
      sessionManager.clearAllSessions();
      sequenceNumbers.current.clear();
      usedNonces.current.clear();
    }

    const pendingExchangeMap = pendingExchanges.current;
    const signingKeyCache = cachedSigningKeys.current;
    const sequenceMap = sequenceNumbers.current;
    const nonceMap = usedNonces.current;
    const pendingSessionMap = pendingSessions.current;
    const queuedMessageMap = pendingMessages.current;
    const seenMessageSet = receivedMessageIds.current;

    return () => {
      disconnectFromWebSocket();
      pendingExchangeMap.clear();
      signingKeyCache.clear();
      sequenceMap.clear();
      nonceMap.clear();
      pendingSessionMap.clear();
      queuedMessageMap.clear();
      seenMessageSet.clear();
    };
  }, [user, keys.eccPrivate, connectToWebSocket, disconnectFromWebSocket]);

  /**
   * Clear error state
   */
  const clearError = useCallback(() => {
    setError(null);
  }, []);

  /**
   * Create a conversation for a contact if it doesn't exist
   */
  const createConversationForContact = useCallback((contact) => {
    if (!conversations.has(contact.id)) {
      setConversations(prev => {
        const newConversations = new Map(prev);
        newConversations.set(contact.id, {
          userId: contact.id,
          username: contact.username,
          publicKey: contact.publicKey,
          messages: [],
          unreadCount: 0,
          lastActivity: new Date().toISOString(),
          isOnline: contact.isOnline || false
        });
        return newConversations;
      });
    }
  }, [conversations]);

  return {
    conversations: Array.from(conversations.values()),
    activeConversation,
    isConnected,
    isLoading,
    error,
    sendMessage,
    loadConversation,
    selectConversation,
    createConversationForContact,
    clearError
  };
}