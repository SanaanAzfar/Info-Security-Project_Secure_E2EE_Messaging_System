/**
 * Main Application Component for Secure End-to-End Encrypted Messaging System
 * Manages authentication state and routing between auth and chat interfaces
 */

import { useState, useEffect } from 'react';
import { useAuth, useKeys } from './hooks/useAuth.js';
import { useMessaging } from './hooks/useMessaging.js';
import { LoginForm } from './components/LoginForm.jsx';
import { RegisterForm } from './components/RegisterForm.jsx';
import { ChatInterface } from './components/ChatInterface.jsx';
import './App.css';

function App() {
  const [authMode, setAuthMode] = useState('login'); // 'login' | 'register'
  const { user, isAuthenticated, isLoading, error, contacts, register, login, logout, addContact, clearError } = useAuth();
  const { keys, loadKeys, clearKeys } = useKeys();
  
  console.log('App component render:', {
    hasUser: !!user,
    userId: user?.id,
    isAuthenticated,
    hasKeys: !!keys,
    keyProps: Object.keys(keys || {}),
    hasEccPrivate: !!keys?.eccPrivate
  });
  
  const messaging = useMessaging(user, keys);

  // Clear keys when user logs out
  useEffect(() => {
    if (!user && !isAuthenticated) {
      console.log('User logged out, clearing keys');
      clearKeys();
    }
  }, [user, isAuthenticated, clearKeys]);

  // Create conversations for existing contacts
  useEffect(() => {
    if (contacts && contacts.length > 0 && messaging.createConversationForContact) {
      contacts.forEach(contact => {
        messaging.createConversationForContact(contact);
      });
    }
  }, [contacts, messaging.createConversationForContact]);

  // Handle authentication error cleanup
  useEffect(() => {
    if (error) {
      const timer = setTimeout(() => {
        clearError();
      }, 5000);
      return () => clearTimeout(timer);
    }
  }, [error, clearError]);

  const handleLogin = async (email, password) => {
    console.log('handleLogin called');
    const loginResult = await login(email, password);
    console.log('Login result:', loginResult);
    
    if (loginResult.success && loginResult.user) {
      // Load user keys after successful login using the returned user data
      console.log('Loading keys for user:', loginResult.user.id);
      const keysLoaded = await loadKeys(loginResult.user.id, password);
      console.log('Keys loaded result:', keysLoaded);
      console.log('Keys state after loading:', keys);
      return true;
    }
    return false;
  };

  const handleRegister = async (userData) => {
    return await register(userData);
  };

  const handleLogout = async () => {
    await logout();
    clearKeys();
  };

  const handleSendMessage = async (receiverId, message) => {
    return await messaging.sendMessage(receiverId, message);
  };

  const handleSelectConversation = async (userId) => {
    messaging.selectConversation(userId);
    // Load conversation history if needed
    if (!messaging.conversations.find(conv => conv.userId === userId)) {
      await messaging.loadConversation(userId);
    }
  };

  const handleContactAdded = (contact) => {
    addContact(contact);
    // Create a conversation for the new contact
    messaging.createConversationForContact(contact);
  };

  // Show loading screen while checking authentication
  if (isLoading && !user) {
    return (
      <div className="app-loading">
        <div className="loading-content">
          <div className="spinner large"></div>
          <h2>Secure Messaging</h2>
          <p>Loading your secure session...</p>
        </div>
      </div>
    );
  }

  // Show chat interface if authenticated
  if (isAuthenticated && user) {
    return (
      <div className="app">
        <div className="app-header">
          <div className="app-title">
            <h1>🔐 Secure Messages</h1>
          </div>
          <div className="user-menu">
            <span className="user-info">
              Welcome, {user.username || user.email}
            </span>
            <button onClick={handleLogout} className="logout-button">
              Logout
            </button>
          </div>
        </div>
        
        <div className="app-content">
          <ChatInterface
            conversations={messaging.conversations}
            activeConversation={messaging.activeConversation}
            onSelectConversation={handleSelectConversation}
            onSendMessage={handleSendMessage}
            user={user}
            isConnected={messaging.isConnected}
            contacts={contacts}
            onContactAdded={handleContactAdded}
          />
        </div>
        
        {messaging.error && (
          <div className="global-error">
            {messaging.error}
            <button onClick={messaging.clearError}>×</button>
          </div>
        )}
      </div>
    );
  }

  // Show authentication forms
  return (
    <div className="app">
      {authMode === 'login' ? (
        <LoginForm
          onLogin={handleLogin}
          onSwitchToRegister={() => setAuthMode('register')}
          isLoading={isLoading}
          error={error}
        />
      ) : (
        <RegisterForm
          onRegister={handleRegister}
          onSwitchToLogin={() => setAuthMode('login')}
          isLoading={isLoading}
          error={error}
        />
      )}
    </div>
  );
}

export default App;
