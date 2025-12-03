const express = require('express');
const { authenticateToken } = require('../middleware/auth');
const { getProfile, getContacts, addContact } = require('../controllers/userController');

const router = express.Router();

/**
 * @swagger
 * /api/users/profile:
 *   get:
 *     summary: Get current user profile
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                     email:
 *                       type: string
 *                     username:
 *                       type: string
 *                     publicKey:
 *                       type: string
 *                     createdAt:
 *                       type: string
 *                       format: date-time
 *                     lastLogin:
 *                       type: string
 *                       format: date-time
 *                       nullable: true
 */
router.get('/profile', authenticateToken, getProfile);

/**
 * @swagger
 * /api/users/contacts:
 *   get:
 *     summary: Get user's contact list
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Contact list retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 contacts:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: string
 *                       username:
 *                         type: string
 *                       publicKey:
 *                         type: string
 *                       addedAt:
 *                         type: string
 *                         format: date-time
 *                       lastSeen:
 *                         type: string
 *                         format: date-time
 *                         nullable: true
 *                       isOnline:
 *                         type: boolean
 */
router.get('/contacts', authenticateToken, getContacts);

/**
 * @swagger
 * /api/users/add-contact:
 *   post:
 *     summary: Add new contact by username
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *     responses:
 *       201:
 *         description: Contact added successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 contact:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                     username:
 *                       type: string
 *                     publicKey:
 *                       type: string
 *                     addedAt:
 *                       type: string
 *                       format: date-time
 */
router.post('/add-contact', authenticateToken, addContact);

module.exports = router;
