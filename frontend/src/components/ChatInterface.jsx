/**
 * Main chat interface component
 */

import { useState, useEffect, useRef } from 'react';
import ContactManager from './ContactManager';
import './Chat.css';

export function ChatInterface({ 
  conversations, 
  activeConversation, 
  onSelectConversation, 
  onSendMessage, 
  user,
  isConnected,
  contacts,
  onContactAdded
}) {
  const [message, setMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [activeConversation?.messages]);

  const handleSendMessage = async (e) => {
    e.preventDefault();
    if (!message.trim() || !activeConv || isLoading) return;

    try {
      setIsLoading(true);
      await onSendMessage(activeConv.userId, message.trim());
      setMessage('');
    } catch (error) {
      console.error('Failed to send message:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    const now = new Date();
    const isToday = date.toDateString() === now.toDateString();
    
    if (isToday) {
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    
    return date.toLocaleDateString([], { 
      month: 'short', 
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getActiveConversationData = () => {
    if (!activeConversation) return null;
    return conversations.find(conv => conv.userId === activeConversation);
  };

  const activeConv = getActiveConversationData();

  return (
    <div className="chat-interface">
      <aside className="conversation-list">
        <ContactManager 
          contacts={contacts}
          onContactAdded={onContactAdded}
        />
        
        <div className="conversation-header">
          <h3>Messages</h3>
          <div className={`connection-status ${isConnected ? 'connected' : 'disconnected'}`}>
            <span className="status-dot"></span>
            {isConnected ? 'Connected' : 'Disconnected'}
          </div>
        </div>
        
        <div className="conversations">
          {conversations.length === 0 ? (
            <div className="no-conversations">
              <p>No conversations yet</p>
              <small>Start a conversation to see it here</small>
            </div>
          ) : (
            conversations.map(conv => (
              <div
                key={conv.userId}
                className={`conversation-item ${activeConversation === conv.userId ? 'active' : ''}`}
                onClick={() => onSelectConversation(conv.userId)}
              >
                <div className="conversation-avatar">
                  {conv.username?.charAt(0).toUpperCase() || '?'}
                </div>
                <div className="conversation-info">
                  <div className="conversation-name">
                    {conv.username || `User ${conv.userId.slice(0, 8)}`}
                  </div>
                  <div className="last-message">
                    {conv.messages.length > 0 
                      ? conv.messages[conv.messages.length - 1].content.slice(0, 50) + '...'
                      : 'No messages yet'
                    }
                  </div>
                </div>
                {conv.unreadCount > 0 && (
                  <div className="unread-badge">{conv.unreadCount}</div>
                )}
              </div>
            ))
          )}
        </div>
      </aside>

      <main className="chat-main">
        {!activeConv ? (
          <div className="no-conversation-selected">
            <div className="welcome-message">
              <h2>Welcome to Secure Messaging</h2>
              <p>Select a conversation to start chatting securely</p>
              <div className="security-features">
                <div className="feature">
                  <span className="feature-icon">🔒</span>
                  <span>End-to-End Encryption</span>
                </div>
                <div className="feature">
                  <span className="feature-icon">🔑</span>
                  <span>Forward Secrecy</span>
                </div>
                <div className="feature">
                  <span className="feature-icon">🛡️</span>
                  <span>Anti-Replay Protection</span>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <>
            <div className="chat-header">
              <div className="chat-user-info">
                <div className="user-avatar">
                  {activeConv.username?.charAt(0).toUpperCase() || '?'}
                </div>
                <div>
                  <div className="user-name">
                    {activeConv.username || `User ${activeConv.userId.slice(0, 8)}`}
                  </div>
                  <div className="encryption-status">
                    🔐 End-to-end encrypted
                  </div>
                </div>
              </div>
            </div>

            <div className="messages-container">
              {activeConv.messages.length === 0 ? (
                <div className="no-messages">
                  <p>Start your secure conversation</p>
                  <small>Messages are encrypted on your device before sending</small>
                </div>
              ) : (
                activeConv.messages.map((msg, index) => (
                  <div
                    key={`${msg.id || 'msg'}-${msg.timestamp || index}-${index}`}
                    className={`message ${msg.senderId === user.id ? 'sent' : 'received'}`}
                  >
                    <div className="message-content">
                      {msg.content}
                      <div className="message-meta">
                        <span className="timestamp">{formatTimestamp(msg.timestamp)}</span>
                        {msg.isEncrypted && <span className="encrypted-badge">🔒</span>}
                      </div>
                    </div>
                  </div>
                ))
              )}
              <div ref={messagesEndRef} />
            </div>

            <form className="message-input-form" onSubmit={handleSendMessage}>
              <div className="message-input-container">
                <input
                  type="text"
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  placeholder="Type your encrypted message..."
                  disabled={isLoading || !isConnected || !activeConv}
                  className="message-input"
                />
                <button
                  type="submit"
                  disabled={isLoading || !message.trim() || !isConnected || !activeConv}
                  className="send-button"
                >
                  {isLoading ? '⏳' : '📤'}
                </button>
              </div>
              {!isConnected && (
                <div className="connection-warning">
                  Disconnected - messages cannot be sent
                </div>
              )}
            </form>
          </>
        )}
      </main>
    </div>
  );
}