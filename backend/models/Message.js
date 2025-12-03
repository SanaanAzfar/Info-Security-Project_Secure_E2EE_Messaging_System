const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  senderId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  receiverId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  encryptedContent: {
    type: String,
    required: true
  },
  iv: {
    type: String,
    required: true
  },
  authTag: {
    type: String,
    required: true
  },
  nonce: {
    type: String,
    required: true
  },
  timestamp: {
    type: Date,
    required: true
  },
  signature: {
    type: String,
    required: true
  },
  messageType: {
    type: String,
    enum: ['text', 'file'],
    default: 'text'
  },
  sequenceNumber: {
    type: Number,
    required: true
  }
}, {
  timestamps: true
});

// Compound index for efficient querying of messages between two users
messageSchema.index({ senderId: 1, receiverId: 1, timestamp: -1 });
messageSchema.index({ receiverId: 1, senderId: 1, timestamp: -1 });

module.exports = mongoose.model('Message', messageSchema);
