import React, { useState } from 'react';
import { apiService } from '../services/api';
import { isValidEmail } from '../utils/helpers';
import './ContactManager.css';

const ContactManager = ({ onContactAdded, contacts }) => {
  const [showAddContact, setShowAddContact] = useState(false);
  const [contactInput, setContactInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // Determine input type and validation
  const getInputType = (value) => {
    if (!value) return 'empty';
    return isValidEmail(value) ? 'email' : 'username';
  };

  const validateInput = (value) => {
    const trimmed = value.trim();
    if (!trimmed) return 'Please enter a username or email';
    
    const inputType = getInputType(trimmed);
    
    if (inputType === 'email') {
      return null; // Email is valid
    } else {
      // Username validation
      if (trimmed.length < 3) return 'Username must be at least 3 characters';
      if (trimmed.length > 30) return 'Username must be less than 30 characters';
      if (!/^[a-zA-Z0-9_]+$/.test(trimmed)) return 'Username can only contain letters, numbers, and underscores';
    }
    
    return null;
  };

  const handleAddContact = async (e) => {
    e.preventDefault();
    const trimmed = contactInput.trim();
    if (!trimmed) return;

    // Validate input
    const validationError = validateInput(trimmed);
    if (validationError) {
      setError(validationError);
      return;
    }

    try {
      setIsLoading(true);
      setError('');
      setSuccess('');

      const inputType = getInputType(trimmed);
      const response = await apiService.addContact(trimmed, inputType);
      
      if (response.success) {
        const identifier = inputType === 'email' ? trimmed : `@${trimmed}`;
        setSuccess(`Added ${identifier} to contacts!`);
        setContactInput('');
        setShowAddContact(false);
        if (onContactAdded) {
          onContactAdded(response.contact);
        }
      }
    } catch (err) {
      console.error('Failed to add contact:', err);
      setError(err.message || 'Failed to add contact');
    } finally {
      setIsLoading(false);
    }
  };

  const clearMessages = () => {
    setError('');
    setSuccess('');
  };

  return (
    <div className="contact-manager">
      <div className="contact-header">
        <h3>Contacts ({contacts?.length || 0})</h3>
        <button 
          className="add-contact-btn"
          onClick={() => setShowAddContact(!showAddContact)}
          title="Add Contact"
        >
          {showAddContact ? '×' : '+'}
        </button>
      </div>

      {showAddContact && (
        <div className="add-contact-form">
          <form onSubmit={handleAddContact}>
            <div className="input-group">
              <input
                type="text"
                value={contactInput}
                onChange={(e) => setContactInput(e.target.value)}
                placeholder={
                  getInputType(contactInput) === 'email' 
                    ? "Enter email address..." 
                    : "Enter username or email..."
                }
                disabled={isLoading}
                className="contact-input"
                autoFocus
              />
              <button
                type="submit"
                disabled={isLoading || !contactInput.trim()}
                className="add-btn"
              >
                {isLoading ? '...' : 'Add'}
              </button>
            </div>
            <div className="input-hint">
              {contactInput.trim() && (
                <small className={`input-type ${getInputType(contactInput) === 'email' ? 'email' : 'username'}`}>
                  {getInputType(contactInput) === 'email' 
                    ? '📧 Adding by email' 
                    : '👤 Adding by username'
                  }
                </small>
              )}
            </div>
          </form>
        </div>
      )}

      {error && (
        <div className="message error">
          {error}
          <button onClick={clearMessages} className="close-btn">×</button>
        </div>
      )}

      {success && (
        <div className="message success">
          {success}
          <button onClick={clearMessages} className="close-btn">×</button>
        </div>
      )}

      <div className="contacts-list">
        {!contacts || contacts.length === 0 ? (
          <div className="no-contacts">
            <p>No contacts yet</p>
            <small>Add someone to start messaging</small>
          </div>
        ) : (
          contacts.map(contact => (
            <div key={contact.id} className="contact-item">
              <div className="contact-avatar">
                {contact.username?.charAt(0).toUpperCase() || '?'}
              </div>
              <div className="contact-info">
                <div className="contact-name">{contact.username}</div>
                <div className="contact-status">
                  <span className={`status-dot ${contact.isOnline ? 'online' : 'offline'}`}></span>
                  {contact.isOnline ? 'Online' : 'Offline'}
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default ContactManager;