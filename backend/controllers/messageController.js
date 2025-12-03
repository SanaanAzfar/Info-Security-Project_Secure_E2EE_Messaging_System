const Message = require('../models/Message');
const Contact = require('../models/Contact');
const mongoose = require('mongoose');

const getMessages = async (req, res) => {
  try {
    const { contactId } = req.params;
    const { limit = 50, offset = 0, before } = req.query;

    // Validate contactId
    if (!mongoose.Types.ObjectId.isValid(contactId)) {
      return res.status(400).json({ message: 'Invalid contact ID' });
    }

    // Check if contact exists (bidirectional)
    const contactExists = await Contact.findOne({
      $or: [
        { userId: req.user.id, contactUserId: contactId },
        { userId: contactId, contactUserId: req.user.id }
      ]
    });

    if (!contactExists) {
      return res.status(404).json({ message: 'Contact not found' });
    }

    // Build query
    const query = {
      $or: [
        { senderId: req.user.id, receiverId: contactId },
        { senderId: contactId, receiverId: req.user.id }
      ]
    };

    if (before && mongoose.Types.ObjectId.isValid(before)) {
      const beforeMessage = await Message.findById(before);
      if (beforeMessage) {
        query.timestamp = { $lt: beforeMessage.timestamp };
      }
    }

    // Get messages with pagination
    const messages = await Message.find(query)
      .sort({ timestamp: -1 })
      .skip(parseInt(offset))
      .limit(parseInt(limit) + 1) // +1 to check if there are more
      .populate('senderId', 'username')
      .populate('receiverId', 'username');

    const hasMore = messages.length > parseInt(limit);
    const resultMessages = hasMore ? messages.slice(0, -1) : messages;

    // Reverse to get chronological order
    resultMessages.reverse();

    const total = await Message.countDocuments(query);

    res.json({
      messages: resultMessages.map(msg => ({
        id: msg._id,
        senderId: msg.senderId._id,
        receiverId: msg.receiverId._id,
        encryptedContent: msg.encryptedContent,
        iv: msg.iv,
        authTag: msg.authTag,
        nonce: msg.nonce,
        timestamp: msg.timestamp.toISOString(),
        signature: msg.signature,
        messageType: msg.messageType
      })),
      hasMore,
      total
    });
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

const sendMessage = async (req, res) => {
  try {
    const {
      receiverId,
      encryptedContent,
      iv,
      authTag,
      nonce,
      timestamp,
      signature,
      messageType = 'text',
      sequenceNumber
    } = req.body;

    // Validate required fields
    if (!receiverId || !encryptedContent || !iv || !authTag || !nonce || !timestamp || !signature) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    // Validate receiverId
    if (!mongoose.Types.ObjectId.isValid(receiverId)) {
      return res.status(400).json({ message: 'Invalid receiver ID' });
    }

    // Check if contact exists (bidirectional)
    const contactExists = await Contact.findOne({
      $or: [
        { userId: req.user.id, contactUserId: receiverId },
        { userId: receiverId, contactUserId: req.user.id }
      ]
    });

    if (!contactExists) {
      return res.status(404).json({ message: 'Contact not found' });
    }

    // Validate sequenceNumber (simple increment, in production might need more complex logic)
    if (typeof sequenceNumber !== 'number' || sequenceNumber < 0) {
      return res.status(400).json({ message: 'Invalid sequence number' });
    }

    // Create message
    const newMessage = new Message({
      senderId: req.user.id,
      receiverId,
      encryptedContent,
      iv,
      authTag,
      nonce,
      timestamp: new Date(timestamp),
      signature,
      messageType,
      sequenceNumber
    });

    await newMessage.save();

    res.status(201).json({
      success: true,
      messageId: newMessage._id,
      timestamp: newMessage.timestamp.toISOString(),
      sequenceNumber: newMessage.sequenceNumber
    });
  } catch (error) {
    console.error('Error sending message:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

module.exports = {
  getMessages,
  sendMessage
};
