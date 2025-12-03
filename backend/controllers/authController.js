const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/User');
const Contact = require('../models/Contact');
const { authenticateToken } = require('../middleware/auth');
const { sendOTPEmail } = require('../utils/emailService');

exports.register = async (req, res) => {
    try {
        const { username, email, password, publicKey } = req.body;

        if (!username || !email || !password || !publicKey) {
            return res.status(400).json({ error: 'Username, email, password, and publicKey are required' });
        }

        if (username.length < 3 || username.length > 50) {
            return res.status(400).json({ error: 'Username must be between 3 and 50 characters' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters long' });
        }

        const existingUser = await User.findOne({ $or: [{ username }, { email }] });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        const user = new User({ username, email, password, publicKey });
        await user.save();

        const token = jwt.sign({ id: user._id, username: user.username, email: user.email }, process.env.JWT_SECRET, { expiresIn: '24h' });

        res.status(201).json({
            success: true,
            token,
            user: {
                id: user._id,
                email: user.email,
                username: user.username,
                publicKey: user.publicKey,
                createdAt: user.createdAt
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

exports.login = async (req, res) => {
    try {
        const { identifier, password } = req.body || {};

        if (!identifier || !password) {
            return res.status(400).json({ error: 'Identifier and password are required' });
        }

        const user = await User.findOne({ $or: [{ username: identifier }, { email: identifier }] });

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const isValidPassword = await user.comparePassword(password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate OTP
        const otp = crypto.randomInt(100000, 999999).toString();
        user.otp = otp;
        user.otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
        await user.save();

        // Send OTP email
        await sendOTPEmail(user.email, otp);

        res.json({ message: 'OTP sent to your email' });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

exports.verifyOtp = async (req, res) => {
    try {
        const { identifier, otp } = req.body;

        if (!identifier || !otp) {
            return res.status(400).json({ error: 'Identifier and OTP are required' });
        }

        const user = await User.findOne({ $or: [{ username: identifier }, { email: identifier }] });

        if (!user || user.otp !== otp || user.otpExpires < new Date()) {
            return res.status(401).json({ error: 'Invalid or expired OTP' });
        }

        // Clear OTP
        user.otp = undefined;
        user.otpExpires = undefined;
        await user.save();

        const token = jwt.sign({ id: user._id, username: user.username, email: user.email }, process.env.JWT_SECRET, { expiresIn: '24h' });

        // Get user's contacts
        const contacts = await Contact.find({ userId: user._id })
            .populate('contactUserId', 'username email publicKey')
            .select('contactUserId addedAt');

        const formattedContacts = contacts.map(contact => ({
            id: contact.contactUserId._id,
            username: contact.contactUserId.username,
            email: contact.contactUserId.email,
            publicKey: contact.contactUserId.publicKey,
            addedAt: contact.addedAt
        }));

        res.json({
            success: true,
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                publicKey: user.publicKey
            },
            contacts: formattedContacts
        });
    } catch (error) {
        console.error('OTP verification error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};
