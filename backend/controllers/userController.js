const User = require('../models/User');
const Contact = require('../models/Contact');

const getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password -otp -otpExpires');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({
      user: {
        id: user._id,
        email: user.email,
        username: user.username,
        publicKey: user.publicKey,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin
      }
    });
  } catch (error) {
    console.error('Error fetching profile:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

const getContacts = async (req, res) => {
  try {
    const contacts = await Contact.find({ userId: req.user.id })
      .populate('contactUserId', 'username publicKey')
      .select('contactUserId addedAt lastSeen isOnline');

    const formattedContacts = contacts.map(contact => ({
      id: contact.contactUserId._id,
      username: contact.contactUserId.username,
      publicKey: contact.contactUserId.publicKey,
      addedAt: contact.addedAt,
      lastSeen: contact.lastSeen,
      isOnline: contact.isOnline
    }));

    res.json({ contacts: formattedContacts });
  } catch (error) {
    console.error('Error fetching contacts:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

const addContact = async (req, res) => {
  try {
    const { username } = req.body;

    if (!username) {
      return res.status(400).json({ message: 'Username is required' });
    }

    // Find the user to add as contact
    const contactUser = await User.findOne({ username });
    if (!contactUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if contact already exists
    const existingContact = await Contact.findOne({
      userId: req.user.id,
      contactUserId: contactUser._id
    });

    if (existingContact) {
      return res.status(409).json({ message: 'Contact already exists' });
    }

    // Create new contact
    const newContact = new Contact({
      userId: req.user.id,
      contactUserId: contactUser._id
    });

    await newContact.save();

    res.status(201).json({
      success: true,
      contact: {
        id: contactUser._id,
        username: contactUser.username,
        publicKey: contactUser.publicKey,
        addedAt: newContact.addedAt
      }
    });
  } catch (error) {
    console.error('Error adding contact:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

module.exports = {
  getProfile,
  getContacts,
  addContact
};
